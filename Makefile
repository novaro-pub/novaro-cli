GOLANGCI_LINT_VERSION := v2.15.0

.PHONY: build test lint check

build: ## ./novaro, against the local stack's API unless NOVARO_API_BASE says otherwise
	go build -trimpath -o novaro .

test:
	go test -race ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

check: ## What CI runs
	test -z "$$(gofmt -l .)"
	go vet ./...
	$(MAKE) lint test
