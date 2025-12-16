.PHONY: build build-setup build-darwin build-windows build-all clean test run run-setup help

# Variables
BINARY_NAME=safechain-agent
SETUP_BINARY_NAME=safechain-setup
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-X 'github.com/AikidoSec/safechain-agent/internal/version.Version=$(VERSION)' \
		-X 'github.com/AikidoSec/safechain-agent/internal/version.BuildTime=$(BUILD_TIME)' \
		-X 'github.com/AikidoSec/safechain-agent/internal/version.GitCommit=$(GIT_COMMIT)'

# Build directories
BIN_DIR=bin
DIST_DIR=dist

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the daemon binary for current platform
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/daemon
	@echo "Binary built: $(BIN_DIR)/$(BINARY_NAME)"

build-setup: ## Build the setup binary for current platform
	@echo "Building $(SETUP_BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SETUP_BINARY_NAME) ./cmd/setup
	@echo "Binary built: $(BIN_DIR)/$(SETUP_BINARY_NAME)"

build-darwin: ## Build release binaries for macOS (amd64 and arm64)
	@echo "Building macOS binaries..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS) -s -w" -trimpath -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/daemon
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS) -s -w" -trimpath -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/daemon
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS) -s -w" -trimpath -o $(BIN_DIR)/$(SETUP_BINARY_NAME)-darwin-amd64 ./cmd/setup
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS) -s -w" -trimpath -o $(BIN_DIR)/$(SETUP_BINARY_NAME)-darwin-arm64 ./cmd/setup
	@echo "macOS binaries built"

build-all: build-darwin build-windows ## Build release binaries for all platforms
	@echo "All binaries built"

run: build ## Run the daemon locally
	$(BIN_DIR)/$(BINARY_NAME)

run-setup: build-setup ## Run the setup locally
	$(BIN_DIR)/$(SETUP_BINARY_NAME)

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "Cleaned build artifacts"
