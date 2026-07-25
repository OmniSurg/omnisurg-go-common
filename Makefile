.PHONY: help lint test build ci

# Pin golangci-lint platform-wide so the linter cannot drift between repos.
# Matches the version the 12 services and admin-bff pin via go run.
GOLANGCI := go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

help:
	@echo "make lint   - golangci-lint (pinned)"
	@echo "make test   - go test -race ./..."
	@echo "make build  - go build ./..."
	@echo "make ci     - lint + test + build (the local CI gate)"

lint:
	$(GOLANGCI) run ./...

test:
	go test -race -count=1 ./...

build:
	go build ./...

ci: lint test build
