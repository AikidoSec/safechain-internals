.PHONY: build install clean test run help version brew-formula brew-install brew-build-all

# Variables
BINARY_NAME=sc-agent
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-X 'github.com/aikido/sc-agent/cmd/daemon.version=$(VERSION)' \
		-X 'github.com/aikido/sc-agent/cmd/daemon.buildTime=$(BUILD_TIME)' \
		-X 'github.com/aikido/sc-agent/cmd/daemon.gitCommit=$(GIT_COMMIT)'

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

install: build ## Install the daemon to /usr/local/bin
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BIN_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY_NAME)"

uninstall: ## Remove the daemon from /usr/local/bin
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstalled $(BINARY_NAME)"

run: build ## Run the daemon locally
	$(BIN_DIR)/$(BINARY_NAME)

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "Cleaned build artifacts"

version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

# Homebrew packaging
package: build-release ## Create Homebrew package
	@echo "Creating Homebrew package..."
	@mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/$(BINARY_NAME)-$(VERSION).tar.gz -C $(BIN_DIR) $(BINARY_NAME)
	@echo "Package created: $(DIST_DIR)/$(BINARY_NAME)-$(VERSION).tar.gz"

# Homebrew targets
brew-formula: ## Build Homebrew formula (builds binaries, creates tarballs, updates formula)
	@./scripts/build-brew-formula.sh

brew-install: brew-formula ## Install Homebrew formula (builds and installs)
	@./scripts/install-brew-formula.sh

brew-build-all: ## Build binaries for both architectures (for Homebrew)
	@echo "Building binaries for both architectures..."
	@mkdir -p $(BIN_DIR) $(DIST_DIR)
	@echo "Building darwin/amd64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
		-ldflags "$(LDFLAGS) -s -w" \
		-trimpath \
		-o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 \
		./cmd/daemon
	@echo "Building darwin/arm64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build \
		-ldflags "$(LDFLAGS) -s -w" \
		-trimpath \
		-o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 \
		./cmd/daemon
	@echo "Binaries built:"
	@ls -lh $(BIN_DIR)/$(BINARY_NAME)-darwin-*

