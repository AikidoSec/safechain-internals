.PHONY: build build-release build-darwin-amd64 build-darwin-arm64 build-windows-amd64 build-windows-arm64 build-proxy build-pkg build-pkg-sign-local install-pkg uninstall-pkg clean test run help

BINARY_NAME=safechain-ultimate
BINARY_NAME_UI=safechain-ultimate-ui
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-X 'github.com/AikidoSec/safechain-internals/internal/version.Version=$(VERSION)' \
		-X 'github.com/AikidoSec/safechain-internals/internal/version.BuildTime=$(BUILD_TIME)' \
		-X 'github.com/AikidoSec/safechain-internals/internal/version.GitCommit=$(GIT_COMMIT)'
RELEASE_LDFLAGS=$(LDFLAGS) -s -w

BIN_DIR=bin
DIST_DIR=dist
PROXY_DIR=proxy

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

help:
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Detected platform: $(DETECTED_OS)/$(DETECTED_ARCH)'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-25s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build:
	@echo "Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT) ./cmd/daemon
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME_UI)$(BINARY_EXT) ./cmd/ui
	@echo "Binaries built:"
	@echo "$(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT)"
	@echo "$(BIN_DIR)/$(BINARY_NAME_UI)$(BINARY_EXT)"

build-release:
	@echo "Building release $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(RELEASE_LDFLAGS)" -trimpath -o $(BIN_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT) ./cmd/daemon
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(RELEASE_LDFLAGS)" -trimpath -o $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH)$(BINARY_EXT) ./cmd/ui
	@echo "Binaries built:"
	@echo "$(BIN_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT)"
	@echo "$(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH)$(BINARY_EXT)"

build-darwin-amd64:
	@$(MAKE) GOOS=darwin GOARCH=amd64 build-release

build-darwin-arm64:
	@$(MAKE) GOOS=darwin GOARCH=arm64 build-release

build-windows-amd64:
	@$(MAKE) GOOS=windows GOARCH=amd64 build-release

build-windows-arm64:
	@$(MAKE) GOOS=windows GOARCH=arm64 build-release

build-proxy:
	@echo "Building safechain-proxy..."
	@cd $(PROXY_DIR) && cargo build --release
	@mkdir -p $(BIN_DIR)
	@cp target/release/safechain-proxy $(BIN_DIR)/safechain-proxy-$(DETECTED_OS)-$(DETECTED_ARCH)
	@echo "Proxy built: $(BIN_DIR)/safechain-proxy-$(DETECTED_OS)-$(DETECTED_ARCH)"

build-pkg:
ifeq ($(DETECTED_OS),darwin)
	@echo "Building macOS PKG installer..."
	@cd packaging/macos && ./build-distribution-pkg.sh -v $(VERSION) -a $(DETECTED_ARCH) -b ../../$(BIN_DIR) -o ../../$(DIST_DIR)
	@echo "PKG built: $(DIST_DIR)/SafeChainUltimate-$(VERSION)-$(DETECTED_ARCH).pkg"
else
	@echo "Error: PKG building is only supported on macOS"
	@exit 1
endif

build-pkg-sign-local:
ifeq ($(DETECTED_OS),darwin)
	@echo "Building complete macOS package..."
	@cd packaging/macos && ./build-and-sign-local.sh $(VERSION)
else
	@echo "Error: PKG building is only supported on macOS"
	@exit 1
endif

install-pkg:
ifeq ($(DETECTED_OS),darwin)
	@cd packaging/macos && ./install-local.sh
else
	@echo "Error: PKG installation is only supported on macOS"
	@exit 1
endif

uninstall-pkg:
ifeq ($(DETECTED_OS),darwin)
	@cd packaging/macos && ./uninstall-local.sh
else
	@echo "Error: PKG uninstallation is only supported on macOS"
	@exit 1
endif

run: build
	$(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT)

test:
	go test -v ./...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "Cleaned build artifacts"
