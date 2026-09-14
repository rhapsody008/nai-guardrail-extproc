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
	ID          string `json:"id"`
	CreatedAt   string `json:"createdAt"`
	CreatedBy   string `json:"createdBy"`
	Name        string `json:"name"`
	Published   bool   `json:"published"`
	Description string `json:"description"`
}

type scannerResult struct {
	ScannerID          string             `json:"scannerId"`
	ScannerVersionMeta scannerVersionMeta `json:"scannerVersionMeta"`
	Outcome            string             `json:"outcome"`
	CustomConfig       bool               `json:"customConfig"`
	StartedDate        string             `json:"startedDate"`
	CompletedDate      string             `json:"completedDate"`
	ScanDirection      string             `json:"scanDirection"`
}

type scanResult struct {
	ScannerResults []scannerResult `json:"scannerResults"`
	Outcome        string          `json:"outcome"`
}

type scanResponse struct {
	ID            string     `json:"id"`
	Result        scanResult `json:"result"`
	RedactedInput string     `json:"redactedInput"`
}

// callGuardrail sends the given text (a request prompt or a response
// completion — same shape either way) to the CAI Scans API and
// reports whether it was flagged unsafe. A scan only counts as safe
// when result.outcome is exactly "cleared" — any other value (a
// specific block reason, or an outcome this code doesn't recognize
// yet) fails closed, consistent with the transport/parsing error
// handling below.
func callGuardrail(ctx context.Context, cfg config, content string) (unsafe bool, err error) {
	reqBody, err := json.Marshal(scanRequest{Input: content})
	if err != nil {
		return true, err
	}

	url := strings.TrimRight(cfg.endpoint, "/") + "/scans"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return true, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cfg.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, err
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
		return true, nil
	}

	var parsed scanResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return true, err
	}

	if parsed.Result.Outcome != "cleared" {
		var flagged []string
		for _, sr := range parsed.Result.ScannerResults {
			if sr.Outcome != "passed" {
				flagged = append(flagged, sr.ScannerID+":"+sr.Outcome)
			}
		}
		log.Printf("scan %s flagged (outcome=%s, scanners=%v), redactedInput=%q",
			parsed.ID, parsed.Result.Outcome, flagged, parsed.RedactedInput)
		return true, nil
	}
	return false, nil
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
// x-guardrail-blocked header.
//
// Both Value and RawValue are set on each header. Evidence from a
// live curl test: header KEYS came through but VALUES were empty
// (content-type missing entirely, x-guardrail-blocked present with no
// value) even with AppendAction forced to overwrite. HeaderValue.Value
// is deprecated in recent Envoy releases in favor of RawValue — this
// Envoy build (v1.37.0) appears to only honor RawValue. Setting both
// covers either case without needing to know which one a given Envoy
// version actually reads.
func blockedResponse(reason string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_OK},
				Body:   blockedGentleBody(),
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
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
					},
				},
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
			prompt := extractPrompt(v.RequestBody.Body)

			ctx, cancel := context.WithTimeout(stream.Context(), 5*time.Second)
			unsafe, err := callGuardrail(ctx, s.cfg, prompt)
			cancel()

			if err != nil {
				// fail closed: block on guardrail-service errors
				log.Printf("guardrail call failed, blocking (fail-closed): %v", err)
				if err := stream.Send(blockedResponse("guardrail_unavailable")); err != nil {
					return err
				}
				continue
			}
			if unsafe {
				log.Printf("guardrail check [request]: BLOCKED")
				if err := stream.Send(blockedResponse("flagged_unsafe")); err != nil {
					return err
				}
				continue
			}
			log.Printf("guardrail check [request]: passed")
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
