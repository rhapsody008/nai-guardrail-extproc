// guardrail_extproc.go
//
// Minimal gRPC ExtProc service implementing
// envoy.service.ext_proc.v3.ExternalProcessor for a prompt guardrail
// that checks both directions, OpenAI-compatible SDK/endpoint only:
//
//   - Pre-call: buffers the request body, extracts the user's prompt,
//     sends it to an OpenAI-compatible endpoint, and if flagged,
//     returns a synthesized 200 chat completion whose assistant
//     message is a gentle refusal (finish_reason: content_filter) —
//     so the client renders it as a normal chat turn, not an error.
//   - Post-call: buffers the response body, extracts the model's
//     completion text, runs it through the same guardrail endpoint,
//     and replaces the response with the same gentle refusal if
//     flagged.
//
// Both checks call the same guardrail model — one classifies a prompt,
// the other classifies a completion, but it's the same request shape
// and the same endpoint.
//
// The real block reason is never shown to the end user (a categorized
// refusal is easy to probe against) — it only goes out in the
// x-guardrail-blocked response header, for your own logs/alerting.
//
// Wire it in via an EnvoyExtensionPolicy targeting the Gateway, with
// processingMode.request.body = Buffered AND response.body = Buffered.
//
// Buffered response mode means the full completion has to arrive
// before the client sees any of it — this breaks SSE streaming to the
// client. That's a known, accepted trade-off for now (see chat); the
// upgrade path if streaming matters later is FULL_DUPLEX_STREAMED mode
// on the response side, which needs a chunked inspect-and-forward loop
// instead of the single buffer-then-decide step used here.
//
// Config is via environment variables (set these from a Kubernetes
// Secret, not inline in the Deployment spec):
//
//   GUARDRAIL_ENDPOINT   OpenAI-compatible base URL, e.g.
//                        http://llama-guard.nai-system.svc:8000/v1
//   GUARDRAIL_API_KEY    Bearer token for that endpoint. This is the
//                        "place to put the API key" — it never touches
//                        the client request, it's only used on the
//                        outbound call from this service to the
//                        guardrail model. Put it in a Secret and mount
//                        it as an env var (see Deployment YAML notes
//                        at the bottom of this file).
//   GUARDRAIL_MODEL      Model name to send in the request body,
//                        e.g. "llama-guard-3-8b". Defaults below.
//   LISTEN_ADDR          gRPC listen address. Defaults to :9002.
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
	model    string
	listen   string
}

func loadConfig() config {
	cfg := config{
		endpoint: os.Getenv("GUARDRAIL_ENDPOINT"),
		apiKey:   os.Getenv("GUARDRAIL_API_KEY"),
		model:    os.Getenv("GUARDRAIL_MODEL"),
		listen:   os.Getenv("LISTEN_ADDR"),
	}
	if cfg.model == "" {
		cfg.model = "llama-guard-3-8b"
	}
	if cfg.listen == "" {
		cfg.listen = ":9002"
	}
	if cfg.endpoint == "" {
		log.Fatal("GUARDRAIL_ENDPOINT is required (OpenAI-compatible base URL)")
	}
	return cfg
}

// ---- OpenAI-compatible client ----

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

const guardrailSystemPrompt = `You are a content safety classifier. ` +
	`Reply with exactly one word: SAFE or UNSAFE. ` +
	`Reply UNSAFE if the user message requests illegal acts, ` +
	`violence, weapons, CSAM, or other clearly harmful content.`

// callGuardrail sends the given text (a request prompt or a response
// completion — same shape either way) to the OpenAI-compatible endpoint
// and reports whether it was flagged unsafe. On any transport or
// parsing error it fails closed (blocks) and returns the error.
func callGuardrail(ctx context.Context, cfg config, content string) (unsafe bool, err error) {
	reqBody, err := json.Marshal(chatRequest{
		Model: cfg.model,
		Messages: []chatMessage{
			{Role: "system", Content: guardrailSystemPrompt},
			{Role: "user", Content: content},
		},
	})
	if err != nil {
		return true, err
	}

	url := strings.TrimRight(cfg.endpoint, "/") + "/chat/completions"
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("guardrail endpoint returned %d: %s", resp.StatusCode, string(body))
		return true, nil
	}

	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return true, err
	}
	if len(parsed.Choices) == 0 {
		return true, nil
	}

	verdict := strings.ToUpper(strings.TrimSpace(parsed.Choices[0].Message.Content))
	return strings.Contains(verdict, "UNSAFE"), nil
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

// extractResponseText pulls the completion text out of an OpenAI-shape
// response body: choices[0].message.content. Falls back to the whole
// body if that doesn't match.
func extractResponseText(body []byte) string {
	var openai chatResponse
	if err := json.Unmarshal(body, &openai); err == nil && len(openai.Choices) > 0 {
		if c := openai.Choices[0].Message.Content; c != "" {
			return c
		}
	}
	return string(body)
}

// ---- ExtProc server ----

type guardrailServer struct {
	extprocv3.UnimplementedExternalProcessorServer
	cfg config
}

const gentleBlockedMessage = "I'm sorry, but I can't help with that request. It's blocked by Guardrail."

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
func blockedResponse(reason string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_OK},
				Body:   blockedGentleBody(),
				Headers: &extprocv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "content-type", Value: "application/json"}},
						{Header: &corev3.HeaderValue{Key: "x-guardrail-blocked", Value: reason}},
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

func passThroughResponseHeaders() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{
				Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE},
			},
		},
	}
}

func continueResponseBody() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{
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
				if err := stream.Send(blockedResponse("flagged_unsafe")); err != nil {
					return err
				}
				continue
			}
			if err := stream.Send(continueRequest()); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if err := stream.Send(passThroughResponseHeaders()); err != nil {
				return err
			}

		case *extprocv3.ProcessingRequest_ResponseBody:
			completion := extractResponseText(v.ResponseBody.Body)

			ctx, cancel := context.WithTimeout(stream.Context(), 5*time.Second)
			unsafe, err := callGuardrail(ctx, s.cfg, completion)
			cancel()

			if err != nil {
				log.Printf("guardrail call failed on response, blocking (fail-closed): %v", err)
				if err := stream.Send(blockedResponse("guardrail_unavailable")); err != nil {
					return err
				}
				continue
			}
			if unsafe {
				if err := stream.Send(blockedResponse("response_flagged_unsafe")); err != nil {
					return err
				}
				continue
			}
			if err := stream.Send(continueResponseBody()); err != nil {
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

	log.Printf("guardrail extproc listening on %s, guardrail endpoint %s, model %s",
		cfg.listen, cfg.endpoint, cfg.model)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve error: %v", err)
	}
}

// ---- deployment notes ----
//
// Remember to set BOTH processingMode.request.body = Buffered and
// processingMode.response.body = Buffered on the EnvoyExtensionPolicy —
// missing the response side means this ResponseBody case never fires.
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
//       value: "http://llama-guard.nai-system.svc:8000/v1"
//     - name: GUARDRAIL_MODEL
//       value: "llama-guard-3-8b"
//     - name: GUARDRAIL_API_KEY
//       valueFrom:
//         secretKeyRef:
//           name: guardrail-extproc-creds
//           key: GUARDRAIL_API_KEY
