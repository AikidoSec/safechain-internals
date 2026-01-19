#!/bin/bash

set -e

# Build macOS Distribution .pkg installer with UI for SafeChain Agent
# This creates a more polished installer with welcome/license/conclusion screens
# Usage: ./build-distribution-pkg.sh -v VERSION -a ARCH [-b BIN_DIR] [-o OUTPUT_DIR]

VERSION=""
ARCH=""
BIN_DIR="./bin"
OUTPUT_DIR="./dist"

# Parse command line arguments
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

# Validate required arguments
if [ -z "$VERSION" ]; then
    echo "Error: VERSION is required (-v)" >&2
    exit 1
fi

if [ -z "$ARCH" ]; then
    echo "Error: ARCH is required (-a)" >&2
    exit 1
fi

# Normalize version for dev builds
if [ "$VERSION" = "dev" ]; then
    PKG_VERSION="0.0.0"
else
    PKG_VERSION="$VERSION"
fi

# Resolve absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_DIR="$(cd "$BIN_DIR" 2>/dev/null && pwd || echo "$PROJECT_DIR/$BIN_DIR")"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

echo "Building macOS Distribution .pkg installer for SafeChain Agent v$VERSION"
echo "  Architecture: $ARCH"
echo "  Binary directory: $BIN_DIR"
echo "  Output directory: $OUTPUT_DIR"
echo "  Project directory: $PROJECT_DIR"

# First, build the component package using the basic build script
echo ""
echo "Step 1: Building component package..."
"$SCRIPT_DIR/build-pkg.sh" -v "$VERSION" -a "$ARCH" -b "$BIN_DIR" -o "$OUTPUT_DIR"

COMPONENT_PKG="$OUTPUT_DIR/SafeChainAgent.$ARCH.pkg"

if [ ! -f "$COMPONENT_PKG" ]; then
    echo "Error: Component package not found at $COMPONENT_PKG" >&2
    exit 1
fi

# Create temporary build directory for distribution
BUILD_DIR="$(mktemp -d)"
trap "rm -rf '$BUILD_DIR'" EXIT

echo ""
echo "Step 2: Building distribution package with UI..."
echo "Using temporary build directory: $BUILD_DIR"

# Copy component package to build directory
cp "$COMPONENT_PKG" "$BUILD_DIR/"

# Copy and customize distribution XML
DIST_XML="$BUILD_DIR/Distribution.xml"
cp "$SCRIPT_DIR/Distribution.xml" "$DIST_XML"
sed -i '' "s/VERSION_PLACEHOLDER/$PKG_VERSION/g" "$DIST_XML"
sed -i '' "s/ARCH_PLACEHOLDER/$ARCH/g" "$DIST_XML"

# Copy resources
RESOURCES_DIR="$BUILD_DIR/Resources"
mkdir -p "$RESOURCES_DIR"
cp "$SCRIPT_DIR/welcome.html" "$RESOURCES_DIR/"
cp "$SCRIPT_DIR/conclusion.html" "$RESOURCES_DIR/"
cp "$SCRIPT_DIR/license.txt" "$RESOURCES_DIR/"
cp "$PROJECT_DIR/packaging/shared/background.png" "$RESOURCES_DIR/"

# Build the distribution package
OUTPUT_DIST_PKG="$OUTPUT_DIR/SafeChainAgent-$VERSION-$ARCH.pkg"

echo "Building distribution package..."
productbuild \
    --distribution "$DIST_XML" \
    --resources "$RESOURCES_DIR" \
    --package-path "$BUILD_DIR" \
    "$OUTPUT_DIST_PKG"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Distribution package built successfully: $OUTPUT_DIST_PKG"
    echo ""
    
    # Calculate checksum
    CHECKSUM=$(shasum -a 256 "$OUTPUT_DIST_PKG" | awk '{print $1}')
    echo "SHA256: $CHECKSUM"
    echo "$CHECKSUM" > "$OUTPUT_DIST_PKG.sha256"
    echo ""
    
    # Display package size
    SIZE=$(du -h "$OUTPUT_DIST_PKG" | awk '{print $1}')
    echo "Package size: $SIZE"
    echo ""
    echo "This is a distribution package with installer UI."
    echo "For GitHub releases, use: SafeChainAgent-$VERSION-$ARCH.pkg"
else
    echo "Error: Distribution package build failed" >&2
    exit 1
fi

exit 0
