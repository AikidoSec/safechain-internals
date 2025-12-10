.PHONY: build clean test run help

# Variables
BINARY_NAME=sc-agent
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-X 'github.com/aikido/sc-agent/internal/version.Version=$(VERSION)' \
		-X 'github.com/aikido/sc-agent/internal/version.BuildTime=$(BUILD_TIME)' \
		-X 'github.com/aikido/sc-agent/internal/version.GitCommit=$(GIT_COMMIT)'

# Build directories
BIN_DIR=bin
DIST_DIR=dist

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the daemon binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/daemon
	@echo "Binary built: $(BIN_DIR)/$(BINARY_NAME)"

build-release: ## Build release binary with optimizations
	@echo "Building release binary..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS) -s -w" -trimpath -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/daemon
	@echo "Release binary built: $(BIN_DIR)/$(BINARY_NAME)"

run: build ## Run the daemon locally
	$(BIN_DIR)/$(BINARY_NAME)

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "Cleaned build artifacts"
