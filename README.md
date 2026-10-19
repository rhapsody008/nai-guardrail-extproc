# nai-guardrail-extproc

A pre-call prompt guardrail for Nutanix AI (NAI). It runs as an Envoy
[external processor](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
attached to the NAI ingress gateway. It sends each request's prompt to
the CalypsoAI (CAI) Scans API before the request reaches the model.

POC — one `dev` environment only.

## How it works

```
client ──► nai-ingress-gateway (Envoy) ──► model
                  │  ▲
     request body │  │ continue / rewrite / block
                  ▼  │
          guardrail-extproc ──► CAI  POST {GUARDRAIL_ENDPOINT}/scans
```

For each request body, the extproc takes the last `user` message of an
OpenAI-style `messages` array. If there is none, it uses the raw body.
It sends that text to CAI, then does one of the following:

| CAI verdict | What the client gets |
| --- | --- |
| Cleared | The request passes through unchanged. |
| Cleared, with a redacted input | The request is forwarded with the last user message replaced by the redacted text. |
| Flagged | A synthesized `200` chat completion with `finish_reason: content_filter`, so chat UIs show a polite refusal instead of an error. The block reason goes only in the `x-guardrail-blocked` response header. |
| CAI unreachable, non-200 or timeout | Same refusal, with reason `guardrail_unavailable` (fails closed). |

The extproc only checks requests, never responses: the
`EnvoyExtensionPolicy` sets no `processingMode.response`. See the header
comment in [guardrail_extproc.go](guardrail_extproc.go) for why.

> **Scope warning.** The policy is attached to the whole gateway, so
> every request body that goes through `nai-ingress-gateway` reaches
> this filter: UI, IAM, oauth2-proxy and MCP, not just model calls. The
> code does not currently filter by path, because the scoping change
> was reverted in `9fb88f0`. So non-chat POST bodies are also sent to
> CAI and can be blocked. `failOpen: true` covers only a broken extproc
> pod, not a CAI failure. Fix the scoping before turning off debug
> logging or setting `failOpen: false`.

## Configuration

Set through environment variables in [deploy/deployment.yaml](deploy/deployment.yaml):

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `GUARDRAIL_ENDPOINT` | yes | — | CAI base URL, e.g. `https://us1.calypsoai.app/backend/v1`. The code appends `/scans`. |
| `GUARDRAIL_API_KEY` | yes | — | From the Secret `guardrail-extproc-creds`. Used only for the call to CAI. |
| `GUARDRAIL_DEBUG` | no | off | `true`/`1`/`yes`/`on` logs each scan request and response, **including raw prompt content**. On in `dev`. |
| `LISTEN_ADDR` | no | `:9002` | gRPC listen address. |

## Repository layout

```
guardrail_extproc.go     the service (single file, package main)
Dockerfile, Makefile     image build and local smoke test
deploy/                  app manifests; CI packages these into an OCI artifact
gitops/                  Flux objects; read from Git by the NKP GitOps source
.github/workflows/       release.yaml: image + manifest artifact to GHCR
DEVOPS.md                release, deploy, rollback and cluster setup
```

## Local development

```bash
make build          # go build → ./guardrail-extproc
make docker-build   # image guardrail-extproc:local
make smoke-test     # build, run detached, check :9002 accepts connections, tear down
make run            # run in the foreground with a dummy endpoint
```

The smoke test only checks that the container starts and listens. It
points `GUARDRAIL_ENDPOINT` at nothing, so every scan fails closed.

To preview the rendered manifests (`kustomize` is built into kubectl):

```bash
kubectl kustomize deploy
kubectl kustomize gitops
```

## Deployment

The service is deployed with GitOps from GHCR. Merging to `main`
releases to the cluster; CI never writes back to Git. For the pipeline,
what a pull request does, rollback and first-time cluster setup, see
**[DEVOPS.md](DEVOPS.md)**.
