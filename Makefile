# Makefile
.PHONY: all ci lint deps vulncheck build test clean

# Default target
all: lint test build

# Full CI pipeline run locally
ci: deps lint test vulncheck

# Run linters
lint:
	golangci-lint run

# Tidy module dependencies
deps:
	go mod tidy

# Run vulnerability check
vulncheck:
	gosec ./...

# Build the plugin (compile-only check; Traefik loads the plugin via Yaegi, not the .so)
build:
	go build -buildmode=plugin -o traefik-plugin-block-useragents.so block_useragents.go

# Run tests
test:
	go test -v ./...

# Clean up generated files
clean:
	rm -f traefik-plugin-block-useragents.so
