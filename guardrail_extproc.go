// guardrail_extproc.go
//
// Minimal gRPC ExtProc service implementing
// envoy.service.ext_proc.v3.ExternalProcessor for a PRE-CALL prompt
// guardrail, OpenAI-compatible SDK/endpoint only:
//
//   Buffers the request body, extracts the user's prompt, sends it to
//   the CAI Scans API, and if flagged, returns a synthesized 200 chat
//   completion whose assistant message is a gentle refusal
//   (finish_reason: content_filter) — so the client renders it as a
//   normal chat turn, not an error.
//
// Post-call (checking the model's completion after generation) was
// deliberately dropped: with Buffered response mode it can only start
// after the entire completion has already been generated, adding a
// full extra sequential LLM call with zero bytes visible to the
// client in the meantime. That pushed total round-trip time close to
// (and in testing, past) an upstream Cloudflare Tunnel timeout that
// isn't configurable from this side. Pre-call only removes that
// failure mode entirely. If post-call moderation is needed later, do
// it as FULL_DUPLEX_STREAMED so it can run alongside a still-streaming
// response instead of after it.
//
// The real block reason is never shown to the end user (a categorized
// refusal is easy to probe against) — it only goes out in the
// x-guardrail-blocked response header, for your own logs/alerting.
//
// Wire it in via an EnvoyExtensionPolicy targeting the relevant
// HTTPRoutes, with processingMode.request.body = Buffered. Do NOT set
// processingMode.response — omitting it entirely means Envoy never
// sends response-phase messages to this service at all.
//
// Config is via environment variables (set these from a Kubernetes
// Secret, not inline in the Deployment spec):
//
//   GUARDRAIL_ENDPOINT   CAI base URL, e.g. https://api.example.com/v1
//                        (this code appends "/scans").
//   GUARDRAIL_API_KEY    Bearer token for that endpoint. This is the
//                        "place to put the API key" — it never touches
//                        the client request, it's only used on the
//                        outbound call from this service to the CAI
//                        Scans API. Put it in a Secret and mount it as
//                        an env var (see Deployment YAML notes at the
//                        bottom of this file).
//   LISTEN_ADDR          gRPC listen address. Defaults to :9002.
//   GUARDRAIL_DEBUG      Set to "true"/"1"/"yes"/"on" to log a single
//                        record line per scan call: the request URL
//                        and body, the response status code, and the
//                        raw response body. Off by default — this
//                        includes raw prompt content and the full CAI
//                        response, so only turn it on where those logs
//                        are appropriately access-controlled.
//
// Build: go build -o guardrail-extproc .
// Deps:
//   google.golang.org/grpc
//   github.com/envoyproxy/go-control-plane

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
)

// ---- config ----

type config struct {
	endpoint string
	apiKey   string
	listen   string
	debug    bool
}

func loadConfig() config {
	cfg := config{
		endpoint: os.Getenv("GUARDRAIL_ENDPOINT"),
		apiKey:   os.Getenv("GUARDRAIL_API_KEY"),
		listen:   os.Getenv("LISTEN_ADDR"),
		debug:    isTruthy(os.Getenv("GUARDRAIL_DEBUG")),
	}
	if cfg.listen == "" {
		cfg.listen = ":9002"
	}
	if cfg.endpoint == "" {
		log.Fatal("GUARDRAIL_ENDPOINT is required (CAI base URL)")
	}
	return cfg
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---- CAI Scans API client ----

// chatMessage mirrors the OpenAI chat message shape used by the
// client's incoming request body (see extractPrompt) — unrelated to
// the CAI Scans API, which takes plain text.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type scanRequest struct {
	Input string `json:"input"`
}

type scannerVersionMeta struct {
	ID   string `json:"id"`
	Name string `json:"name"` // scanner package, e.g. "2026-09"
}

type scannerResult struct {
	ScannerID     string             `json:"scannerId"`
	VersionMeta   scannerVersionMeta `json:"scannerVersionMeta"`
	Outcome       string             `json:"outcome"` // "passed" | "failed"
	Message       string             `json:"message"`
	ScanDirection string             `json:"scanDirection"`
	Data          struct {
		Type       string `json:"type"`
		TokenUsage int    `json:"tokenUsage"`
	} `json:"data"`
}

type scanResponse struct {
	ID     string `json:"id"`
	Result struct {
		ScannerResults []scannerResult `json:"scannerResults"`
		// Observed values: "cleared", "flagged". Treat anything that is not
		// exactly "cleared" as a block — new outcome strings must fail closed.
		Outcome string `json:"outcome"`
	} `json:"result"`
	RedactedInput string `json:"redactedInput"`
}

// verdict is the normalised outcome of one scan.
type verdict struct {
	ScanID   string
	Blocked  bool
	Outcome  string   // raw outcome string, for logging
	Failed   []string // "<scanner-id> (<package>)" per non-passing scanner
	Tokens   int      // summed across all scanners
	Redacted string
}

// normalise reduces a scan response to a verdict.
//
// Fails closed: only an explicit "cleared" outcome with no failing scanner
// lets the request through. An empty, unknown or unparseable outcome blocks.
func (sr scanResponse) normalise() verdict {
	v := verdict{
		ScanID:   sr.ID,
		Outcome:  sr.Result.Outcome,
		Redacted: sr.RedactedInput,
	}
	for _, s := range sr.Result.ScannerResults {
		v.Tokens += s.Data.TokenUsage
		if s.Outcome != "passed" {
			entry := s.ScannerID
			if s.VersionMeta.Name != "" {
				entry += " (" + s.VersionMeta.Name + ")"
			}
			if s.Message != "" {
				entry += ": " + s.Message
			}
			v.Failed = append(v.Failed, entry)
		}
	}
	v.Blocked = sr.Result.Outcome != "cleared" || len(v.Failed) > 0
	return v
}

// callGuardrail sends the given text (a request prompt) to the CAI Scans
// API and normalises the response into a verdict, including the redacted
// form of the prompt as returned by the scan API. A scan only counts as
// safe when result.outcome is exactly "cleared" and every scanner reported
// "passed" — any other value (a specific block reason, or an outcome this
// code doesn't recognize yet) fails closed, consistent with the
// transport/parsing error handling below. verdict.Redacted is "" when the
// API returned nothing usable; callers must treat that as "no redaction
// available" rather than "redact to empty".
func callGuardrail(ctx context.Context, cfg config, prompt string) (verdict, error) {
	start := time.Now()

	reqBody, err := json.Marshal(scanRequest{Input: prompt})
	if err != nil {
		return verdict{}, err
	}

	url := strings.TrimRight(cfg.endpoint, "/") + "/scans"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return verdict{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cfg.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return verdict{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return verdict{}, err
	}

	// GUARDRAIL_DEBUG record line: the call, the status, and the exact
	// bytes returned, flattened to one line so a log pipeline can
	// index/grep it as a single record. Off by default since it
	// includes raw prompt content and the full scan response.
	if cfg.debug {
		log.Printf("[debug] POST %s reqBody=%s status=%d respBody=%s",
			url, oneLine(reqBody), resp.StatusCode, oneLine(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("scan API returned %d: %s", resp.StatusCode, string(respBody))
		return verdict{}, fmt.Errorf("scan API returned %d", resp.StatusCode)
	}

	var sr scanResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return verdict{}, fmt.Errorf("decoding scan response: %w", err)
	}

	v := sr.normalise()
	log.Printf("scan id=%s outcome=%s blocked=%t failed=%d tokens=%d latency=%s",
		v.ScanID, v.Outcome, v.Blocked, len(v.Failed), v.Tokens,
		time.Since(start).Round(time.Millisecond))
	return v, nil
}

// oneLine collapses whitespace (including embedded newlines) so a
// logged blob of JSON stays on a single log line.
func oneLine(b []byte) string {
	return strings.Join(strings.Fields(string(b)), " ")
}

// extractPrompt pulls the last user message out of an OpenAI-style
// chat request body. Falls back to treating the whole body as the
// prompt if it doesn't parse as expected.
func extractPrompt(body []byte) string {
	var generic struct {
		Messages []chatMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &generic); err == nil && len(generic.Messages) > 0 {
		for i := len(generic.Messages) - 1; i >= 0; i-- {
			if generic.Messages[i].Role == "user" {
				return generic.Messages[i].Content
			}
		}
	}
	return string(body)
}

// redactBody replaces the last user message's content with redacted and
// returns the re-serialised body. Returns ok=false when the body is not a
// shape it can safely rewrite, in which case the caller must forward the
// original bytes unmodified.
//
// Uses a generic map rather than a typed struct so that fields this service
// does not model — tools, response_format, stream_options, vendor extensions
// — survive the round trip untouched.
func redactBody(body []byte, redacted string) ([]byte, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	rawMsgs, present := doc["messages"]
	if !present {
		return nil, false
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(rawMsgs, &msgs); err != nil {
		return nil, false
	}

	for i := len(msgs) - 1; i >= 0; i-- {
		var role string
		if err := json.Unmarshal(msgs[i]["role"], &role); err != nil {
			continue
		}
		if role != "user" {
			continue
		}
		// Only rewrite plain string content. Multimodal content arrives as an
		// array of parts; extractPrompt cannot read those either, so there is
		// nothing coherent to substitute and we leave the body alone.
		var content string
		if err := json.Unmarshal(msgs[i]["content"], &content); err != nil {
			return nil, false
		}
		newContent, err := json.Marshal(redacted)
		if err != nil {
			return nil, false
		}
		msgs[i]["content"] = newContent

		rebuilt, err := json.Marshal(msgs)
		if err != nil {
			return nil, false
		}
		doc["messages"] = rebuilt
		out, err := json.Marshal(doc)
		if err != nil {
			return nil, false
		}
		return out, true
	}
	return nil, false
}

// ---- ExtProc server ----

type guardrailServer struct {
	extprocv3.UnimplementedExternalProcessorServer
	cfg config
}

const gentleBlockedMessage = "I'm sorry, but I can't help with that request."

// blockedGentleBody builds a synthetic OpenAI chat-completion response
// body carrying the gentle refusal as the assistant's message content,
// with finish_reason set to the standard "content_filter" value. This
// is what makes the SDK/chat UI show it as a normal assistant turn
// instead of throwing an error.
func blockedGentleBody() []byte {
	body := map[string]any{
		"id":     "guardrail-blocked",
		"object": "chat.completion",
		"model":  "guardrail",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": gentleBlockedMessage,
				},
				"finish_reason": "content_filter",
			},
		},
	}
	b, _ := json.Marshal(body)
	return b
}

// blockedResponse returns 200 with a synthesized gentle assistant
// message so OpenAI-compatible clients render it as a normal chat
// turn rather than raising an SDK-level error. The real block reason
// (for your own logs/alerting, not shown to the end user) goes in the
// x-guardrail-blocked header. scanID, when non-empty, goes in a
// separate x-guardrail-scan-id header — that's what lets you pull the
// full scanner breakdown from the CalypsoAI console for a block a
// user reports as a false positive.
//
// Deliberately *not* included: the failing scanner IDs. Those tell a
// caller which detector fired, which is a probing aid for anyone
// searching for a phrasing that gets through — logs, not the wire.
//
// Both Value and RawValue are set on each header. Evidence from a
// live curl test: header KEYS came through but VALUES were empty
// (content-type missing entirely, x-guardrail-blocked present with no
// value) even with AppendAction forced to overwrite. HeaderValue.Value
// is deprecated in recent Envoy releases in favor of RawValue — this
// Envoy build (v1.37.0) appears to only honor RawValue. Setting both
// covers either case without needing to know which one a given Envoy
// version actually reads.
func blockedResponse(reason, scanID string) *extprocv3.ProcessingResponse {
	headers := []*corev3.HeaderValueOption{
		{
			Header: &corev3.HeaderValue{
				Key:      "content-type",
				Value:    "application/json",
				RawValue: []byte("application/json"),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		},
		{
			Header: &corev3.HeaderValue{
				Key:      "x-guardrail-blocked",
				Value:    reason,
				RawValue: []byte(reason),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		},
	}
	if scanID != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:      "x-guardrail-scan-id",
				Value:    scanID,
				RawValue: []byte(scanID),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_OK},
				Body:    blockedGentleBody(),
				Headers: &extprocv3.HeaderMutation{SetHeaders: headers},
			},
		},
	}
}

func continueRequest() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
			},
		},
	}
}

// continueWithBody forwards the request upstream with body replaced.
//
// Envoy is responsible for reconciling content-length after a buffered body
// mutation. Verify this on your build: if the backend rejects requests or
// hangs after redaction changes the body length, that reconciliation is the
// first thing to check.
func continueWithBody(body []byte) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{
					Status: extprocv3.CommonResponse_CONTINUE,
					BodyMutation: &extprocv3.BodyMutation{
						Mutation: &extprocv3.BodyMutation_Body{Body: body},
					},
				},
			},
		},
	}
}

func passThroughHeaders() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{
				Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
			},
		},
	}
}

func (s *guardrailServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch v := req.Request.(type) {

		case *extprocv3.ProcessingRequest_RequestHeaders:
			if err := stream.Send(passThroughHeaders()); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			original := v.RequestBody.Body
			prompt := extractPrompt(original)

			ctx, cancel := context.WithTimeout(stream.Context(), 5*time.Second)
			gv, err := callGuardrail(ctx, s.cfg, prompt)
			cancel()

			if err != nil {
				log.Printf("guardrail check [request]: BLOCKED (guardrail_unavailable): %v", err)
				if err := stream.Send(blockedResponse("guardrail_unavailable", "")); err != nil {
					return err
				}
				continue
			}
			if gv.Blocked {
				log.Printf("guardrail check [request]: BLOCKED scan=%s outcome=%s failed=[%s]",
					gv.ScanID, gv.Outcome, strings.Join(gv.Failed, "; "))
				if err := stream.Send(blockedResponse("flagged_unsafe", gv.ScanID)); err != nil {
					return err
				}
				continue
			}

			// Cleared. Substitute the redacted prompt only when the scan
			// actually changed something and the body is a shape we can
			// rewrite; otherwise forward the original bytes untouched.
			if gv.Redacted != "" && gv.Redacted != prompt {
				if newBody, ok := redactBody(original, gv.Redacted); ok {
					log.Printf("guardrail check [request]: passed scan=%s (redacted, %d -> %d bytes)",
						gv.ScanID, len(original), len(newBody))
					if err := stream.Send(continueWithBody(newBody)); err != nil {
						return err
					}
					continue
				}
				log.Printf("guardrail check [request]: passed scan=%s (redaction available but body not rewritable, forwarding original)", gv.ScanID)
			} else {
				log.Printf("guardrail check [request]: passed scan=%s", gv.ScanID)
			}
			if err := stream.Send(continueRequest()); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders, *extprocv3.ProcessingRequest_ResponseBody:
			// Should never actually arrive — processingMode.response is
			// deliberately unset in the EnvoyExtensionPolicy, so Envoy
			// shouldn't send these. Pass through harmlessly if it
			// somehow does (e.g. policy misconfiguration) rather than
			// erroring the whole stream.
			if err := stream.Send(&extprocv3.ProcessingResponse{}); err != nil {
				return err
			}

		default:
			// anything else (trailers, etc.): pass through unmodified.
			if err := stream.Send(&extprocv3.ProcessingResponse{}); err != nil {
				return err
			}
		}
	}
}

func main() {
	cfg := loadConfig()

	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", cfg.listen, err)
	}

	grpcServer := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(grpcServer, &guardrailServer{cfg: cfg})

	log.Printf("guardrail extproc listening on %s, guardrail endpoint %s",
		cfg.listen, cfg.endpoint)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve error: %v", err)
	}
}

// ---- deployment notes ----
//
// Set processingMode.request.body = Buffered on the
// EnvoyExtensionPolicy. Do NOT set processingMode.response at all —
// its presence, even with no body mode specified, is enough to make
// Envoy start sending response-phase messages to this service.
//
// Put the API key in a Secret, not a ConfigMap or inline env value:
//
//   kubectl create secret generic guardrail-extproc-creds \
//     --namespace nai-system \
//     --from-literal=GUARDRAIL_API_KEY='<key>'
//
// Then in the Deployment container spec:
//
//   env:
//     - name: GUARDRAIL_ENDPOINT
//       value: "https://api.example.com/v1"
//     - name: GUARDRAIL_API_KEY
//       valueFrom:
//         secretKeyRef:
//           name: guardrail-extproc-creds
//           key: GUARDRAIL_API_KEY
