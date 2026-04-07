.PHONY: build build-release build-darwin-amd64 build-darwin-arm64 build-darwin-universal build-windows-amd64 build-proxy build-l7-proxy-universal build-l4-proxy build-l4-proxy-universal build-l4-proxy-macos build-pkg build-pkg-sign-local install-pkg uninstall-pkg clean test run help

BINARY_NAME=endpoint-protection
BINARY_NAME_UI=endpoint-protection-ui
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-X 'github.com/AikidoSec/safechain-internals/internal/version.Version=$(VERSION)' \
		-X 'github.com/AikidoSec/safechain-internals/internal/version.BuildTime=$(BUILD_TIME)' \
		-X 'github.com/AikidoSec/safechain-internals/internal/version.GitCommit=$(GIT_COMMIT)'
RELEASE_LDFLAGS=$(LDFLAGS) -s -w

BIN_DIR=bin
DIST_DIR=dist

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
	@echo "Binaries built:"
	@echo "  $(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT)"
ifeq ($(GOOS),darwin)
	@cd ui && CGO_ENABLED=1 wails3 package
	@rm -rf $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).app
	@cp -R ui/bin/$(BINARY_NAME_UI).app $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).app
	@echo "  $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).app"
else ifeq ($(GOOS),windows)
	@cd ui && CGO_ENABLED=1 wails3 package
	@rm -rf $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).exe
	@cp -R ui/bin/$(BINARY_NAME_UI).exe $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).exe
	@echo "  $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).exe"
endif

build-release:
	@echo "Building release $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(RELEASE_LDFLAGS)" -trimpath -o $(BIN_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT) ./cmd/daemon
	@echo "Binaries built:"
	@echo "  $(BIN_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(BINARY_EXT)"
ifeq ($(GOOS),darwin)
	@cd ui && CGO_ENABLED=1 wails3 package
	@rm -rf $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).app
	@cp -R ui/bin/$(BINARY_NAME_UI).app $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).app
	@echo "  $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).app"
else
	@cd ui && CGO_ENABLED=1 wails3 package
	@rm -rf $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).exe
	@cp -R ui/bin/$(BINARY_NAME_UI).exe $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).exe
	@echo "  $(BIN_DIR)/$(BINARY_NAME_UI)-$(GOOS)-$(GOARCH).exe"
endif

build-darwin-amd64:
	@"$(MAKE)" GOOS=darwin GOARCH=amd64 build-release

build-darwin-arm64:
	@"$(MAKE)" GOOS=darwin GOARCH=arm64 build-release

build-darwin-universal: build-darwin-amd64 build-darwin-arm64
	@echo "Creating universal binaries..."
	@lipo -create $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 \
		-output $(BIN_DIR)/$(BINARY_NAME)-darwin-universal
	@rm -rf $(BIN_DIR)/$(BINARY_NAME_UI)-darwin-universal.app
	@cp -R $(BIN_DIR)/$(BINARY_NAME_UI)-darwin-amd64.app $(BIN_DIR)/$(BINARY_NAME_UI)-darwin-universal.app
	@lipo -create \
		"$(BIN_DIR)/$(BINARY_NAME_UI)-darwin-amd64.app/Contents/MacOS/$(BINARY_NAME_UI)" \
		"$(BIN_DIR)/$(BINARY_NAME_UI)-darwin-arm64.app/Contents/MacOS/$(BINARY_NAME_UI)" \
		-output "$(BIN_DIR)/$(BINARY_NAME_UI)-darwin-universal.app/Contents/MacOS/$(BINARY_NAME_UI)"
	@echo "Universal binaries created:"
	@lipo -info $(BIN_DIR)/$(BINARY_NAME)-darwin-universal
	@lipo -info "$(BIN_DIR)/$(BINARY_NAME_UI)-darwin-universal.app/Contents/MacOS/$(BINARY_NAME_UI)"

build-windows-amd64:
	@"$(MAKE)" GOOS=windows GOARCH=amd64 build-release

build-windows-arm64:
	@"$(MAKE)" GOOS=windows GOARCH=arm64 build-release

build-l7-proxy:
	@echo "Building safechain-l7-proxy..."
	@cargo build --release --bin safechain-l7-proxy
	@mkdir -p $(BIN_DIR)
	@cp target/release/safechain-l7-proxy $(BIN_DIR)/safechain-l7-proxy-$(DETECTED_OS)-$(DETECTED_ARCH)
	@echo "Proxy built: $(BIN_DIR)/safechain-l7-proxy-$(DETECTED_OS)-$(DETECTED_ARCH)"

build-l7-proxy-universal:
	@echo "Building safechain-l7-proxy for x86_64-apple-darwin..."
	@rustup target add x86_64-apple-darwin 2>/dev/null || true
	@cargo build --release --bin safechain-l7-proxy --target x86_64-apple-darwin
	@echo "Building safechain-l7-proxy for aarch64-apple-darwin..."
	@rustup target add aarch64-apple-darwin 2>/dev/null || true
	@cargo build --release --bin safechain-l7-proxy --target aarch64-apple-darwin
	@mkdir -p $(BIN_DIR)
	@lipo -create \
		target/x86_64-apple-darwin/release/safechain-l7-proxy \
		target/aarch64-apple-darwin/release/safechain-l7-proxy \
		-output $(BIN_DIR)/safechain-l7-proxy-darwin-universal
	@echo "Universal proxy built:"
	@lipo -info $(BIN_DIR)/safechain-l7-proxy-darwin-universal

build-l4-proxy:
	@echo "Building safechain-l4-proxy..."
	@cargo build --release --bin safechain-l4-proxy
	@mkdir -p $(BIN_DIR)
	@cp target/release/safechain-l4-proxy $(BIN_DIR)/safechain-l4-proxy-$(DETECTED_OS)-$(DETECTED_ARCH)
	@echo "Proxy built: $(BIN_DIR)/safechain-l4-proxy-$(DETECTED_OS)-$(DETECTED_ARCH)"

build-l4-proxy-universal:
	@echo "Building safechain-l4-proxy for x86_64-apple-darwin..."
	@rustup target add x86_64-apple-darwin 2>/dev/null || true
	@cargo build --release --bin safechain-l4-proxy --target x86_64-apple-darwin
	@echo "Building safechain-l4-proxy for aarch64-apple-darwin..."
	@rustup target add aarch64-apple-darwin 2>/dev/null || true
	@cargo build --release --bin safechain-l4-proxy --target aarch64-apple-darwin
	@mkdir -p $(BIN_DIR)
	@lipo -create \
		target/x86_64-apple-darwin/release/safechain-l4-proxy \
		target/aarch64-apple-darwin/release/safechain-l4-proxy \
		-output $(BIN_DIR)/safechain-l4-proxy-darwin-universal
	@echo "Universal proxy built:"
	@lipo -info $(BIN_DIR)/safechain-l4-proxy-darwin-universal

L4_DERIVED_DATA=.aikido/xcode/safechain-l4-proxy-release
L4_APP_NAME=Aikido Proxy.app

build-l4-proxy-macos:
ifeq ($(DETECTED_OS),darwin)
	@echo "Building safechain-lib-l4-proxy-macos for x86_64-apple-darwin..."
	@rustup target add x86_64-apple-darwin 2>/dev/null || true
	@cargo build --release -p safechain-lib-l4-proxy-macos --target x86_64-apple-darwin
	@echo "Building safechain-lib-l4-proxy-macos for aarch64-apple-darwin..."
	@rustup target add aarch64-apple-darwin 2>/dev/null || true
	@cargo build --release -p safechain-lib-l4-proxy-macos --target aarch64-apple-darwin
	@mkdir -p target/universal
	@lipo -create \
		target/x86_64-apple-darwin/release/libsafechain_lib_l4_proxy_macos.a \
		target/aarch64-apple-darwin/release/libsafechain_lib_l4_proxy_macos.a \
		-output target/universal/libsafechain_lib_l4_proxy_macos.a
	@echo "Universal static lib built:"
	@lipo -info target/universal/libsafechain_lib_l4_proxy_macos.a
	@echo "Generating Xcode project..."
	@cd packaging/macos/xcode/l4-proxy && xcodegen generate
	@echo "Building macOS L4 proxy app..."
	@cd packaging/macos/xcode/l4-proxy && xcodebuild \
		-project AikidoEndpointL4Proxy.xcodeproj \
		-scheme AikidoEndpointL4ProxyHost \
		-configuration Release \
		-derivedDataPath "$(CURDIR)/$(L4_DERIVED_DATA)" \
		"ARCHS=x86_64 arm64" \
		ONLY_ACTIVE_ARCH=NO \
		clean build
	@mkdir -p $(BIN_DIR)
	@rm -rf "$(BIN_DIR)/$(L4_APP_NAME)"
	@ditto "$(L4_DERIVED_DATA)/Build/Products/Release/$(L4_APP_NAME)" "$(BIN_DIR)/$(L4_APP_NAME)"
	@echo "macOS L4 proxy app built: $(BIN_DIR)/$(L4_APP_NAME)"
else
	@echo "Error: build-l4-proxy-macos is only supported on macOS"
	@exit 1
endif

build-pkg:
ifeq ($(DETECTED_OS),darwin)
	@echo "Building macOS PKG installer..."
	@cd packaging/macos && ./build-distribution-pkg.sh -v $(VERSION) -a universal -b ../../$(BIN_DIR) -o ../../$(DIST_DIR)
	@echo "PKG built: $(DIST_DIR)/EndpointProtection-$(VERSION).pkg"
else
	@echo "Error: PKG building is only supported on macOS"
	@exit 1
endif

build-pkg-sign-local:
ifeq ($(DETECTED_OS),darwin)
	@echo "Building complete macOS package..."
	@cd packaging/macos && ./build-and-sign-local.sh $(VERSION)
else ifeq ($(DETECTED_OS),windows)
	@echo "Building Windows binaries for $(DETECTED_ARCH)..."
	@"$(MAKE)" build-windows-$(DETECTED_ARCH) VERSION=$(VERSION)
	@echo "Building Windows proxy (safechain-l7-proxy)..."
	@cargo build --release -p safechain-l7-proxy --target x86_64-pc-windows-msvc
	@mkdir -p $(BIN_DIR)
	@cp target/x86_64-pc-windows-msvc/release/safechain-l7-proxy.exe $(BIN_DIR)/SafeChainL7Proxy.exe
	@cp $(BIN_DIR)/$(BINARY_NAME)-windows-$(DETECTED_ARCH).exe $(BIN_DIR)/EndpointProtection.exe
	@cp $(BIN_DIR)/$(BINARY_NAME_UI)-windows-$(DETECTED_ARCH).exe $(BIN_DIR)/EndpointProtectionUI.exe
	@echo "Building Windows MSI installer..."
	@powershell -ExecutionPolicy Bypass -File packaging/windows/build-msi.ps1 -Version "$(VERSION)" -BinDir ".\$(BIN_DIR)" -OutputDir "."
	@echo "Windows MSI build completed."
else
	@echo "Error: PKG building is only supported on macOS"
	@exit 1
endif

install-pkg:
ifeq ($(DETECTED_OS),darwin)
ifdef TOKEN
	@echo "$(TOKEN)" > /tmp/aikido_endpoint_token.txt
endif
	@cd packaging/macos && ./install-local.sh
else ifeq ($(DETECTED_OS),windows)
	@echo "Installing Windows MSI package..."
	@msiexec /i EndpointProtection.msi
else
	@echo "Error: PKG installation is only supported on macOS"
	@exit 1
endif

uninstall-pkg:
ifeq ($(DETECTED_OS),darwin)
	sudo "/Applications/Aikido Endpoint Protection.app/Contents/Resources/scripts/uninstall"
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
