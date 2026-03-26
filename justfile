# credkit - shared credential management primitives
# Run `just --list` to see available commands

set shell := ["bash", "-uc"]

# Default recipe: run tests
default: test

# ============================================================================
# Setup
# ============================================================================

# Sync tool dependencies
sync-tools:
    go mod tidy -modfile=tools.go.mod

# ============================================================================
# Testing
# ============================================================================

# Run all tests
test:
    go tool -modfile=tools.go.mod gotestsum --format testdox -- ./...

# Run tests with race detector
test-race:
    go tool -modfile=tools.go.mod gotestsum --format testdox -- -race ./...

# Run tests with coverage report
test-cover:
    go tool -modfile=tools.go.mod gotestsum --format testdox -- -race -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# ============================================================================
# Linting & Formatting
# ============================================================================

# Run golangci-lint
lint:
    go tool -modfile=tools.go.mod golangci-lint run

# Run go vet
vet:
    go vet ./...

# Format code
fmt:
    gofmt -w .

# Check if code is formatted
fmt-check:
    #!/usr/bin/env bash
    unformatted=$(gofmt -l .)
    if [ -n "$unformatted" ]; then
        echo "Code is not formatted. Run 'just fmt'"
        echo "$unformatted"
        exit 1
    fi

# Tidy go.mod
tidy:
    go mod tidy

# ============================================================================
# CI / Development
# ============================================================================

# Run all checks (CI)
ci: test-race lint vet fmt-check

# Development workflow: format, lint, test
dev: fmt lint test
