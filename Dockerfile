# syntax=docker/dockerfile:1

FROM golang:1.22-bookworm AS builder
WORKDIR /src

COPY go.mod ./
COPY guardrail_extproc.go ./main.go

# no go.sum is checked in, so resolve + pin it here before the build
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/guardrail-extproc .

# alpine: has a shell for debugging, unlike distroless — the binary
# itself is still static (CGO_ENABLED=0) so musl vs glibc doesn't
# matter here. CA certs are copied from the builder stage rather than
# apk-fetched here, since apk hitting the public Alpine CDN can fail
# in environments that intercept/restrict outbound TLS (as here) —
# the builder stage already has a trusted bundle, it had to in order
# to pull the Go modules.
FROM alpine:3.20
RUN addgroup -S guardrail && adduser -S guardrail -G guardrail
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/guardrail-extproc /guardrail-extproc

EXPOSE 9002
USER guardrail:guardrail
ENTRYPOINT ["/guardrail-extproc"]