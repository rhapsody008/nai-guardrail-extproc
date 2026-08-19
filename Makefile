IMAGE       ?= guardrail-extproc:local
CONTAINER   := guardrail-extproc-smoke
PORT        ?= 9002

.PHONY: build docker-build run stop smoke-test clean

## build: compile locally (requires Go + network access to module proxies)
build:
	go mod tidy
	CGO_ENABLED=0 go build -o guardrail-extproc .

## docker-build: build the container image
docker-build:
	docker build -t $(IMAGE) .

## run: start the container in the foreground with a dummy guardrail
## endpoint, so you can watch startup logs directly. Ctrl+C to stop.
## Point GUARDRAIL_ENDPOINT at a real OpenAI-compatible endpoint to
## actually exercise the guardrail call path.
run: docker-build
	docker run --rm -it \
		--name $(CONTAINER) \
		-p $(PORT):9002 \
		-e GUARDRAIL_ENDPOINT=http://localhost:1/v1 \
		-e GUARDRAIL_MODEL=llama-guard-3-8b \
		-e GUARDRAIL_API_KEY=dummy-local-test-key \
		$(IMAGE)

## smoke-test: build, start detached, confirm the gRPC port is actually
## accepting connections, then tear down. This is the "does the
## container even come up" check — it does not exercise the guardrail
## call path, since GUARDRAIL_ENDPOINT points nowhere real.
smoke-test: docker-build
	-docker rm -f $(CONTAINER) >/dev/null 2>&1
	docker run -d \
		--name $(CONTAINER) \
		-p $(PORT):9002 \
		-e GUARDRAIL_ENDPOINT=http://localhost:1/v1 \
		-e GUARDRAIL_MODEL=llama-guard-3-8b \
		-e GUARDRAIL_API_KEY=dummy-local-test-key \
		$(IMAGE)
	@echo "waiting for container to come up..."
	@sleep 2
	@if ! docker ps --filter "name=$(CONTAINER)" --filter "status=running" | grep -q $(CONTAINER); then \
		echo "container exited early, logs:"; \
		docker logs $(CONTAINER); \
		docker rm -f $(CONTAINER) >/dev/null 2>&1; \
		exit 1; \
	fi
	@if ! (exec 3<>/dev/tcp/127.0.0.1/$(PORT)) 2>/dev/null; then \
		echo "port $(PORT) not accepting connections, logs:"; \
		docker logs $(CONTAINER); \
		docker rm -f $(CONTAINER) >/dev/null 2>&1; \
		exit 1; \
	fi
	@echo "OK: container is up and listening on :$(PORT)"
	docker logs $(CONTAINER)
	docker rm -f $(CONTAINER) >/dev/null 2>&1

stop:
	-docker rm -f $(CONTAINER) >/dev/null 2>&1

clean: stop
	-docker rmi $(IMAGE) >/dev/null 2>&1
	rm -f guardrail-extproc