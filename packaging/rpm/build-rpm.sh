#!/bin/bash

set -e

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
        h)
            echo "Usage: $0 -v VERSION -a ARCH [-b BIN_DIR] [-o OUTPUT_DIR]"
            echo "  -v VERSION      Version number (e.g., 1.0.0)"
            echo "  -a ARCH         Architecture (arm64 or amd64)"
            echo "  -b BIN_DIR      Binary directory (default: ./bin)"
            echo "  -o OUTPUT_DIR   Output directory (default: ./dist)"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Error: VERSION is required (-v)" >&2
    exit 1
fi

if [ -z "$ARCH" ]; then
    echo "Error: ARCH is required (-a)" >&2
    exit 1
fi

if [ "$VERSION" = "dev" ]; then
    PKG_VERSION="0.0.0"
else
    PKG_VERSION="$VERSION"
fi

case "$ARCH" in
    amd64)  RPM_ARCH="x86_64" ;;
    arm64)  RPM_ARCH="aarch64" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH (expected amd64 or arm64)" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_DIR="$(cd "$BIN_DIR" 2>/dev/null && pwd || echo "$PROJECT_DIR/$BIN_DIR")"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

echo "Building Linux RPM installer for SafeChain Ultimate v$VERSION"
echo "  Architecture: $ARCH ($RPM_ARCH)"
echo "  Binary directory: $BIN_DIR"
echo "  Output directory: $OUTPUT_DIR"
echo "  Project directory: $PROJECT_DIR"

AGENT_BIN="$BIN_DIR/safechain-ultimate-linux-$ARCH"
AGENT_UI_BIN="$BIN_DIR/safechain-ultimate-ui-linux-$ARCH"
PROXY_BIN="$BIN_DIR/safechain-proxy-linux-$ARCH"

if [ ! -f "$AGENT_BIN" ]; then
    echo "Error: safechain-ultimate binary not found at $AGENT_BIN" >&2
    exit 1
fi

if [ ! -f "$AGENT_UI_BIN" ]; then
    echo "Error: safechain-ultimate-ui binary not found at $AGENT_UI_BIN" >&2
    exit 1
fi

if [ ! -f "$PROXY_BIN" ]; then
    echo "Error: safechain-proxy binary not found at $PROXY_BIN" >&2
    exit 1
fi

BUILD_DIR="$(mktemp -d)"
trap "rm -rf '$BUILD_DIR'" EXIT

echo "Using temporary build directory: $BUILD_DIR"

RPMBUILD_DIR="$BUILD_DIR/rpmbuild"
mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

echo "Copying binaries to SOURCES..."
cp "$AGENT_BIN" "$RPMBUILD_DIR/SOURCES/safechain-ultimate"
cp "$AGENT_UI_BIN" "$RPMBUILD_DIR/SOURCES/safechain-ultimate-ui"
cp "$PROXY_BIN" "$RPMBUILD_DIR/SOURCES/safechain-proxy"

echo "Copying packaging files to SOURCES..."
cp "$SCRIPT_DIR/safechain-ultimate.service" "$RPMBUILD_DIR/SOURCES/"
cp "$SCRIPT_DIR/scripts/uninstall" "$RPMBUILD_DIR/SOURCES/"

echo "Copying spec file..."
cp "$SCRIPT_DIR/safechain-ultimate.spec" "$RPMBUILD_DIR/SPECS/"

echo "Building RPM package..."
rpmbuild -bb \
    --define "_topdir $RPMBUILD_DIR" \
    --define "_pkg_version $PKG_VERSION" \
    --target "$RPM_ARCH" \
    "$RPMBUILD_DIR/SPECS/safechain-ultimate.spec"

RPM_FILE=$(find "$RPMBUILD_DIR/RPMS/$RPM_ARCH/" -name "safechain-ultimate-*.rpm" | head -1)

if [ -z "$RPM_FILE" ]; then
    echo "Error: RPM file not found after build" >&2
    exit 1
fi

OUTPUT_RPM="$OUTPUT_DIR/SafeChainUltimate-$VERSION-$ARCH.rpm"
cp "$RPM_FILE" "$OUTPUT_RPM"

echo ""
echo "✓ RPM package built successfully: $OUTPUT_RPM"
echo ""

CHECKSUM=$(sha256sum "$OUTPUT_RPM" | awk '{print $1}')
echo "SHA256: $CHECKSUM"
echo "$CHECKSUM" > "$OUTPUT_RPM.sha256"
echo ""

echo "Package information:"
rpm -qip "$OUTPUT_RPM"
echo ""

SIZE=$(du -h "$OUTPUT_RPM" | awk '{print $1}')
echo "Package size: $SIZE"

exit 0
