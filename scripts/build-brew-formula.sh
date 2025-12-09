#!/bin/bash
set -e

# Script to build Homebrew formula for sc-agent
# This script builds binaries for both architectures, creates tarballs,
# calculates checksums, and updates the formula file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
FORMULA_DIR="$PROJECT_ROOT/Formula"
FORMULA_FILE="$FORMULA_DIR/sc-agent.rb"
DIST_DIR="$PROJECT_ROOT/dist"
BIN_DIR="$PROJECT_ROOT/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
VERSION="${VERSION:-0.1.0}"
BINARY_NAME="sc-agent"

# Functions
error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${GREEN}✓${NC} $1"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    if ! command -v go &> /dev/null; then
        error "Go is not installed or not in PATH"
    fi
    
    if ! command -v shasum &> /dev/null && ! command -v sha256sum &> /dev/null; then
        error "sha256sum or shasum is required but not found"
    fi
    
    SHA_CMD="shasum -a 256"
    if command -v sha256sum &> /dev/null; then
        SHA_CMD="sha256sum"
    fi
    
    info "Prerequisites check passed"
}

# Get version from git tag or use provided version
get_version() {
    if [ -n "$VERSION" ] && [ "$VERSION" != "dev" ]; then
        echo "$VERSION"
    else
        # Try to get version from git tag
        GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")
        if [ -n "$GIT_TAG" ]; then
            echo "${GIT_TAG#v}"  # Remove 'v' prefix if present
        else
            warn "No version specified and no git tag found. Using default: 0.1.0"
            echo "0.1.0"
        fi
    fi
}

# Build binary for a specific platform
build_binary() {
    local os=$1
    local arch=$2
    local output_dir=$3
    
    info "Building for $os/$arch..."
    
    BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    
    LDFLAGS="-X 'github.com/aikido/sc-agent/cmd/daemon.version=$VERSION' \
             -X 'github.com/aikido/sc-agent/cmd/daemon.buildTime=$BUILD_TIME' \
             -X 'github.com/aikido/sc-agent/cmd/daemon.gitCommit=$GIT_COMMIT'"
    
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build \
        -ldflags "$LDFLAGS -s -w" \
        -trimpath \
        -o "$output_dir/$BINARY_NAME" \
        ./cmd/daemon
    
    info "Built binary: $output_dir/$BINARY_NAME"
}

# Create tarball and calculate checksum
create_tarball() {
    local arch=$1
    local tarball_name="${BINARY_NAME}-${VERSION}-darwin-${arch}.tar.gz"
    local tarball_path="$DIST_DIR/$tarball_name"
    
    info "Creating tarball: $tarball_name"
    
    # Create temporary directory for tarball contents
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    # Copy binary to temp directory
    cp "$BIN_DIR/$BINARY_NAME" "$temp_dir/"
    
    # Create tarball
    tar -czf "$tarball_path" -C "$temp_dir" "$BINARY_NAME"
    
    # Calculate SHA256
    local checksum
    if command -v sha256sum &> /dev/null; then
        checksum=$(sha256sum "$tarball_path" | cut -d' ' -f1)
    else
        checksum=$(shasum -a 256 "$tarball_path" | cut -d' ' -f1)
    fi
    
    # Output info messages to stderr so they don't get captured in command substitution
    info "Tarball created: $tarball_path" >&2
    info "SHA256: $checksum" >&2
    
    # Only output the checksum to stdout (for command substitution)
    echo "$checksum"
}

# Update formula with checksums
update_formula() {
    local amd64_checksum=$1
    local arm64_checksum=$2
    
    info "Updating formula with checksums..."
    
    # Check if file exists and is readable
    if [ ! -r "$FORMULA_FILE" ]; then
        error "Cannot read formula file: $FORMULA_FILE"
    fi
    
    # Use a temporary file approach to avoid permission issues
    local temp_file=$(mktemp)
    local use_temp=false
    
    # If file is not writable, we'll use temp file and replace at the end
    if [ ! -w "$FORMULA_FILE" ]; then
        warn "Formula file is not writable, using temporary file approach..."
        use_temp=true
        # Try to read from backup if it exists and is readable
        if [ -r "$FORMULA_FILE.bak" ]; then
            cp "$FORMULA_FILE.bak" "$temp_file"
        else
            # Read the original file (even if not writable, we can read it)
            cp "$FORMULA_FILE" "$temp_file"
        fi
    else
        # File is writable, create backup and work with original
        cp "$FORMULA_FILE" "$FORMULA_FILE.bak" || {
            warn "Could not create backup, continuing anyway..."
        }
        cp "$FORMULA_FILE" "$temp_file"
    fi
    
    # Work with temp_file for all modifications
    local work_file="$temp_file"
    
    # Update version
    sed -i.bak2 "s/version \"[^\"]*\"/version \"$VERSION\"/" "$work_file"
    rm -f "$work_file.bak2"
    
    # Update URLs
    sed -i.bak2 "s|url \"[^\"]*darwin-amd64[^\"]*\"|url \"https://github.com/aikido/sc-agent/releases/download/v$VERSION/$BINARY_NAME-$VERSION-darwin-amd64.tar.gz\"|" "$work_file"
    sed -i.bak2 "s|url \"[^\"]*darwin-arm64[^\"]*\"|url \"https://github.com/aikido/sc-agent/releases/download/v$VERSION/$BINARY_NAME-$VERSION-darwin-arm64.tar.gz\"|" "$work_file"
    rm -f "$work_file.bak2"
    
    # Update SHA256 checksums using the Python script
    info "Updating checksums using Python script..."
    if python3 "$SCRIPT_DIR/update-formula-checksums.py" "$work_file" "$amd64_checksum" "$arm64_checksum"; then
        info "Checksums updated successfully"
    else
        error "Failed to update checksums in formula file"
    fi
    
    # Move the updated file back to the original location
    # If we need sudo, try it; otherwise just move
    if [ "$use_temp" = true ]; then
        # Try to move without sudo first
        if mv "$work_file" "$FORMULA_FILE" 2>/dev/null; then
            info "Updated formula file"
        else
            # If that fails, we need sudo - but we can't prompt, so warn user
            warn "Cannot write to formula file. Please run manually:"
            warn "  sudo mv $work_file $FORMULA_FILE"
            warn "  sudo chown \$(whoami) $FORMULA_FILE"
            warn "Or fix permissions first: sudo chown \$(whoami) $FORMULA_FILE"
            error "Cannot update formula file due to permissions"
        fi
    else
        mv "$work_file" "$FORMULA_FILE"
    fi
    
    # Clean up temp file if it still exists
    rm -f "$temp_file"
    
    info "Formula updated: $FORMULA_FILE"
}

# Main execution
main() {
    echo "=========================================="
    echo "Building Homebrew Formula"
    echo "=========================================="
    
    # Get version
    VERSION=$(get_version)
    info "Version: $VERSION"
    
    # Check prerequisites
    check_prerequisites
    
    # Create directories
    mkdir -p "$BIN_DIR" "$DIST_DIR" "$FORMULA_DIR"
    
    # Check formula file permissions early
    if [ -f "$FORMULA_FILE" ] && [ ! -w "$FORMULA_FILE" ]; then
        warn "Formula file is not writable (may be owned by root)"
        warn "Attempting to fix permissions..."
        if [ -r "$FORMULA_FILE.bak" ] && [ -w "$FORMULA_FILE.bak" ]; then
            info "Restoring from backup file with correct permissions..."
            cp "$FORMULA_FILE.bak" "$FORMULA_FILE" 2>/dev/null || {
                error "Cannot fix permissions. Please run:\n  sudo chown \$(whoami) $FORMULA_FILE\n  chmod 644 $FORMULA_FILE"
            }
        else
            error "Formula file is not writable. Please run:\n  sudo chown \$(whoami) $FORMULA_FILE\n  chmod 644 $FORMULA_FILE"
        fi
    fi
    
    # Clean previous builds
    info "Cleaning previous builds..."
    rm -rf "$BIN_DIR"/* "$DIST_DIR"/*
    
    # Build for both architectures
    info "Building binaries for both architectures..."
    
    # Build amd64
    build_binary "darwin" "amd64" "$BIN_DIR"
    # Capture only the checksum (info messages go to stderr)
    AMD64_CHECKSUM=$(create_tarball "amd64" 2>/dev/null)
    
    # Clean binary directory for next build
    rm -f "$BIN_DIR/$BINARY_NAME"
    
    # Build arm64
    build_binary "darwin" "arm64" "$BIN_DIR"
    # Capture only the checksum (info messages go to stderr)
    ARM64_CHECKSUM=$(create_tarball "arm64" 2>/dev/null)
    
    # Update formula
    update_formula "$AMD64_CHECKSUM" "$ARM64_CHECKSUM"
    
    echo ""
    echo "=========================================="
    echo "Build Complete!"
    echo "=========================================="
    info "Version: $VERSION"
    info "AMD64 checksum: $AMD64_CHECKSUM"
    info "ARM64 checksum: $ARM64_CHECKSUM"
    echo ""
    info "Tarballs created in: $DIST_DIR"
    info "Formula updated: $FORMULA_FILE"
    echo ""
    echo "Next steps:"
    echo "  1. Review the formula: $FORMULA_FILE"
    echo "  2. Test the formula: brew install --build-from-source $FORMULA_FILE"
    echo "  3. Create a git tag: git tag v$VERSION"
    echo "  4. Push tag and create GitHub release with tarballs"
}

# Run main function
main

