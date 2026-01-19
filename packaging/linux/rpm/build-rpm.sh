#!/bin/bash
set -e

usage() {
    echo "Usage: $0 -v VERSION -a ARCH [-b BIN_DIR] [-o OUTPUT_DIR]"
    echo ""
    echo "Options:"
    echo "  -v VERSION    Version number (required, e.g., 1.0.0 or dev)"
    echo "  -a ARCH       Architecture (required, arm64 or amd64)"
    echo "  -b BIN_DIR    Binary directory (optional, default: ./bin)"
    echo "  -o OUTPUT_DIR Output directory (optional, default: ./dist)"
    echo "  -h            Show this help message"
    exit 1
}

VERSION=""
ARCH=""
BIN_DIR="./bin"
OUTPUT_DIR="./dist"

while getopts "v:a:b:o:h" opt; do
    case $opt in
        v) VERSION="$OPTARG" ;;
        a) ARCH="$OPTARG" ;;
        b) BIN_DIR="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$VERSION" ] || [ -z "$ARCH" ]; then
    echo "Error: VERSION and ARCH are required"
    usage
fi

if [ "$VERSION" = "dev" ]; then
    RPM_VERSION="0.0.0"
else
    RPM_VERSION="$VERSION"
fi

case "$ARCH" in
    amd64) RPM_ARCH="x86_64" ;;
    arm64) RPM_ARCH="aarch64" ;;
    *) echo "Error: Invalid architecture. Use 'amd64' or 'arm64'"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

BIN_DIR="$(cd "$BIN_DIR" 2>/dev/null && pwd)" || { echo "Error: Binary directory not found: $BIN_DIR"; exit 1; }

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

AGENT_BIN="$BIN_DIR/safechain-agent-linux-$ARCH"
PROXY_BIN="$BIN_DIR/safechain-proxy-linux-$ARCH"

if [ ! -f "$AGENT_BIN" ]; then
    echo "Error: safechain-agent binary not found at $AGENT_BIN"
    exit 1
fi

if [ ! -f "$PROXY_BIN" ]; then
    echo "Error: safechain-proxy binary not found at $PROXY_BIN"
    exit 1
fi

echo "Building RPM package for SafeChain Agent v$VERSION ($RPM_ARCH)"
echo "  Binary directory: $BIN_DIR"
echo "  Output directory: $OUTPUT_DIR"

BUILD_ROOT=$(mktemp -d)
trap "rm -rf $BUILD_ROOT" EXIT

mkdir -p "$BUILD_ROOT/bin"
cp "$AGENT_BIN" "$BUILD_ROOT/bin/safechain-agent"
cp "$PROXY_BIN" "$BUILD_ROOT/bin/safechain-proxy"
chmod 755 "$BUILD_ROOT/bin/safechain-agent"
chmod 755 "$BUILD_ROOT/bin/safechain-proxy"

RPM_OUTPUT="$OUTPUT_DIR/SafeChainAgent-$VERSION-$ARCH.rpm"

rpmbuild -bb \
    --define "_version $RPM_VERSION" \
    --define "_bindir_source $BUILD_ROOT/bin" \
    --define "_sourcedir $SCRIPT_DIR" \
    --define "_rpmdir $OUTPUT_DIR" \
    --define "_build_name_fmt %%{NAME}-$VERSION-$ARCH.rpm" \
    --target "$RPM_ARCH" \
    "$SCRIPT_DIR/safechain-agent.spec"

if [ -f "$RPM_OUTPUT" ]; then
    echo ""
    echo "RPM built successfully: $RPM_OUTPUT"
    
    SHA256=$(sha256sum "$RPM_OUTPUT" | awk '{print $1}')
    echo "SHA256: $SHA256"
    echo "$SHA256" > "$RPM_OUTPUT.sha256"
else
    echo "Error: RPM file not found at expected location: $RPM_OUTPUT"
    echo "Checking output directory contents:"
    ls -la "$OUTPUT_DIR"
    exit 1
fi
