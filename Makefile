# Makefile for PAM Parser Go Library

.PHONY: all build build-tool test clean install lint fmt vet examples check-golangci-lint-version update-golangci-lint

# Variables
GO := go
GET := $(shell if command -v curl >/dev/null 2>&1; then echo "curl -sSfL"; elif command -v wget >/dev/null 2>&1; then echo "wget -O- -nv"; else echo "echo 'Error: Neither curl nor wget found' && exit 1"; fi)
GOLANGCI_LINT := $(shell if [ -x "./bin/golangci-lint" ]; then echo "./bin/golangci-lint"; else echo "golangci-lint"; fi)
PACKAGE := github.com/StephenBrown2/pamparser
BINARY_NAME := pam-tool
EXAMPLES_DIR := examples
CMD_DIR := cmd

all: lint test build build-tool

# Build the library
build:
	$(GO) build ./...

# Build the command-line tool
build-tool:
	$(GO) build -o $(BINARY_NAME) ./$(CMD_DIR)/$(BINARY_NAME)

# Run tests
test:
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Run benchmarks
bench:
	$(GO) test -bench=. ./...

# Check golangci-lint version (requires version 2.x)
check-golangci-lint-version:
	@echo "Checking golangci-lint version..."
	@version=$$($(GOLANGCI_LINT) version 2>/dev/null | grep -o 'golangci-lint has version [0-9]\+\.[0-9]\+\.[0-9]\+' | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1) && \
	if [ -z "$$version" ]; then \
		echo "Error: golangci-lint not found or unable to determine version"; \
		echo "Please install golangci-lint version 2.x from https://golangci-lint.run/welcome/install/"; \
		echo "Or run 'make update-golangci-lint' to install it locally"; \
		exit 1; \
	fi && \
	major_version=$$(echo $$version | cut -d. -f1) && \
	if [ "$$major_version" -lt "2" ]; then \
		echo "Error: golangci-lint version $$version detected, but version 2.x is required"; \
		echo "Please install golangci-lint version 2.x from https://golangci-lint.run/welcome/install/"; \
		echo "Or run 'make update-golangci-lint' to install it locally"; \
		exit 1; \
	fi && \
	echo "✓ golangci-lint version $$version (compatible)"

# Update golangci-lint (optionally specify VERSION=x.y.z, defaults to latest)
# Usage: make update-golangci-lint              # installs latest
#        make update-golangci-lint VERSION=2.2.2 # installs specific version
update-golangci-lint:
	@UPDATE_SCRIPT=https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh; \
	if [ -n "$(VERSION)" ]; then \
		echo "Downloading and installing golangci-lint v$(VERSION) to ./bin/..."; \
		$(GET) $$UPDATE_SCRIPT | sh -s v$(VERSION) && \
		echo "✓ golangci-lint updated to v$(VERSION) in ./bin/"; \
	else \
		echo "Downloading and installing latest golangci-lint to ./bin/..."; \
		$(GET) $$UPDATE_SCRIPT | sh -s && \
		echo "✓ golangci-lint updated to latest version in ./bin/"; \
	fi
	@echo "The Makefile will automatically use the local version when available"
	@echo "Run 'make check-golangci-lint-version' to verify the installation"

# Lint code with golangci-lint (includes formatting, vet, and other linters)
lint: check-golangci-lint-version fmt
	$(GOLANGCI_LINT) run

# Format code (use golangci-lint for consistent formatting)
fmt: check-golangci-lint-version
	$(GOLANGCI_LINT) fmt

# Vet code (included in golangci-lint, but kept for compatibility)
vet: check-golangci-lint-version
	$(GOLANGCI_LINT) run --enable-only govet

# Build examples
examples:
	$(GO) build -o $(EXAMPLES_DIR)/basic/basic ./$(EXAMPLES_DIR)/basic
	$(GO) build -o $(EXAMPLES_DIR)/grouping/grouping ./$(EXAMPLES_DIR)/grouping
	$(GO) build -o $(EXAMPLES_DIR)/insertion/insertion ./$(EXAMPLES_DIR)/insertion

# Run examples
run-examples: examples
	@echo "=== Running Basic Example ==="
	./$(EXAMPLES_DIR)/basic/basic
	@echo ""
	@echo "=== Running Grouping Example ==="
	./$(EXAMPLES_DIR)/grouping/grouping
	@echo ""
	@echo "=== Running Insertion Example ==="
	./$(EXAMPLES_DIR)/insertion/insertion

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Clean build artifacts
clean:
	$(GO) clean ./...
	rm -f $(BINARY_NAME)
	rm -f $(EXAMPLES_DIR)/basic/basic
	rm -f $(EXAMPLES_DIR)/grouping/grouping
	rm -f $(EXAMPLES_DIR)/insertion/insertion
	rm -f coverage.out coverage.html
	rm -rf ./bin

# Install the tool
install: build-tool
	cp $(BINARY_NAME) /usr/local/bin/

# Generate documentation
docs:
	$(GO) doc -all $(PACKAGE)

# Check for security vulnerabilities using nancy (https://github.com/sonatype-nexus-community/nancy)
security:
	@command -v nancy >/dev/null 2>&1 || { echo >&2 "nancy is not installed. Install it with: go install github.com/sonatype-nexus-community/nancy@latest"; exit 1; }
	$(GO) list -json -m all | nancy sleuth

# Run all checks
check: lint test

# Run build without linting (for development)
dev: test build

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Run lint, test, and build"
	@echo "  build        - Build the library"
	@echo "  build-tool   - Build the command-line tool"
	@echo "  test         - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  bench        - Run benchmarks"
	@echo "  check-golangci-lint-version - Check that golangci-lint version 2.x is installed"
	@echo "  update-golangci-lint - Download and install golangci-lint to ./bin/ (latest or VERSION=x.y.z)"
	@echo "  lint         - Run golangci-lint (includes formatting, vet, and other linters)"
	@echo "                 Note: May report issues that should be addressed"
	@echo "  fmt          - Format code using golangci-lint --fix"
	@echo "  vet          - Vet code (also included in lint)"
	@echo "  examples     - Build examples"
	@echo "  run-examples - Build and run examples"
	@echo "  deps         - Install dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install the tool to /usr/local/bin"
	@echo "  security     - Check for security vulnerabilities (requires 'nancy', install with: go install github.com/sonatype-nexus-community/nancy@latest)"
	@echo "  check        - Run lint and tests"
	@echo "  dev          - Run tests and build (skip linting for faster development)"
	@echo "  help         - Show this help"
