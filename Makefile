.PHONY: build build-setup build-release build-release-setup build-darwin-amd64 build-darwin-arm64 build-windows-amd64 build-windows-arm64 clean test run run-setup help

BINARY_NAME=safechain-agent
SETUP_BINARY_NAME=safechain-setup
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-X 'github.com/AikidoSec/safechain-agent/internal/version.Version=$(VERSION)' \
		-X 'github.com/AikidoSec/safechain-agent/internal/version.BuildTime=$(BUILD_TIME)' \
		-X 'github.com/AikidoSec/safechain-agent/internal/version.GitCommit=$(GIT_COMMIT)'
RELEASE_LDFLAGS=$(LDFLAGS) -s -w

BIN_DIR=bin

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
UNAME_M := $(shell uname -m 2>/dev/null || echo x86_64)

ifeq ($(UNAME_S),Darwin)
    DETECTED_OS := darwin
else ifeq ($(UNAME_S),Linux)
    DETECTED_OS := linux
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    DETECTED_OS := windows
else ifneq (,$(findstring MSYS,$(UNAME_S)))
    DETECTED_OS := windows
else
    DETECTED_OS := windows
endif

ifeq ($(UNAME_M),x86_64)
    DETECTED_ARCH := amd64
else ifeq ($(UNAME_M),amd64)
    DETECTED_ARCH := amd64
else ifeq ($(UNAME_M),arm64)
    DETECTED_ARCH := arm64
else ifeq ($(UNAME_M),aarch64)
    DETECTED_ARCH := arm64
else
    DETECTED_ARCH := amd64
endif

GOOS ?= $(DETECTED_OS)
GOARCH ?= $(DETECTED_ARCH)

ifeq ($(GOOS),windows)
    BINARY_EXT := .exe
else
    BINARY_EXT :=
endif

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Detected platform: $(DETECTED_OS)/$(DETECTED_ARCH)'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-25s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the daemon binary for current platform
	@echo "Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT) ./cmd/daemon
	@echo "Binary built: $(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT)"

build-setup: ## Build the setup binary for current platform
	@echo "Building $(SETUP_BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SETUP_BINARY_NAME)$(BINARY_EXT) ./cmd/setup
	@echo "Binary built: $(BIN_DIR)/$(SETUP_BINARY_NAME)$(BINARY_EXT)"

build-release: ## Build release daemon binary for current platform (stripped)
	@echo "Building release $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(RELEASE_LDFLAGS)" -trimpath -o $(BIN_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT) ./cmd/daemon
	@echo "Binary built: $(BIN_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT)"

build-release-setup: ## Build release setup binary for current platform (stripped)
	@echo "Building release $(SETUP_BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(RELEASE_LDFLAGS)" -trimpath -o $(BIN_DIR)/$(SETUP_BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT) ./cmd/setup
	@echo "Binary built: $(BIN_DIR)/$(SETUP_BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT)"

build-darwin-amd64: ## Build release binaries for macOS amd64
	@$(MAKE) GOOS=darwin GOARCH=amd64 build-release build-release-setup

build-darwin-arm64: ## Build release binaries for macOS arm64
	@$(MAKE) GOOS=darwin GOARCH=arm64 build-release build-release-setup

build-windows-amd64: ## Build release binaries for Windows amd64
	@$(MAKE) GOOS=windows GOARCH=amd64 build-release build-release-setup

build-windows-arm64: ## Build release binaries for Windows arm64
	@$(MAKE) GOOS=windows GOARCH=arm64 build-release build-release-setup

run: build ## Run the daemon locally
	$(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT)

run-setup: build-setup ## Run the setup locally
	$(BIN_DIR)/$(SETUP_BINARY_NAME)$(BINARY_EXT)

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR)
	@echo "Cleaned build artifacts"
