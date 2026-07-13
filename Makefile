.PHONY: help lint test build ci

help:
	@echo "make lint   - golangci-lint"
	@echo "make test   - go test -race ./..."
	@echo "make build  - go build ./..."
	@echo "make ci     - lint + test + build (the local CI gate)"

lint:
	golangci-lint run ./...

test:
	go test -race -count=1 ./...

build:
	go build ./...

ci: lint test build
