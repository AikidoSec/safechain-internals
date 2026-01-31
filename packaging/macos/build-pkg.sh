#!/bin/bash

set -e

# Build macOS .pkg installer for SafeChain Ultimate
# Usage: ./build-pkg.sh -v VERSION -a ARCH [-b BIN_DIR] [-o OUTPUT_DIR]

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

echo "Building macOS .pkg installer for SafeChain Ultimate v$VERSION"
echo "  Architecture: $ARCH"
echo "  Binary directory: $BIN_DIR"
echo "  Output directory: $OUTPUT_DIR"
echo "  Project directory: $PROJECT_DIR"

# Verify binaries exist
AGENT_BIN="$BIN_DIR/safechain-ultimate-darwin-$ARCH"
AGENT_UI_BIN="$BIN_DIR/safechain-ultimate-ui-darwin-$ARCH"
PROXY_BIN="$BIN_DIR/safechain-proxy-darwin-$ARCH"

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

# Create temporary build directory
BUILD_DIR="$(mktemp -d)"
trap "rm -rf '$BUILD_DIR'" EXIT

echo "Using temporary build directory: $BUILD_DIR"

# Create package directory structure
PKG_ROOT="$BUILD_DIR/pkg_root"
PKG_SCRIPTS="$BUILD_DIR/scripts"
INSTALL_DIR="$PKG_ROOT/Library/Application Support/AikidoSecurity/SafeChainUltimate"
LAUNCHDAEMONS_DIR="$PKG_ROOT/Library/LaunchDaemons"
LOGS_DIR="$PKG_ROOT/Library/Logs/AikidoSecurity/SafeChainUltimate"
APP_BUNDLE_DIR="$INSTALL_DIR/SafeChainUltimate.app"

mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$LAUNCHDAEMONS_DIR"
mkdir -p "$LOGS_DIR"
mkdir -p "$PKG_SCRIPTS"
mkdir -p "$APP_BUNDLE_DIR/Contents/MacOS"
mkdir -p "$APP_BUNDLE_DIR/Contents/Resources"

# Create placeholder file in logs directory to ensure it's included in package
touch "$LOGS_DIR/.keep"
chmod 644 "$LOGS_DIR/.keep"

# Copy binaries into app bundle
echo "Copying binaries..."
cp "$AGENT_BIN" "$INSTALL_DIR/bin/safechain-ultimate"
cp "$AGENT_UI_BIN" "$INSTALL_DIR/bin/safechain-ultimate-ui"
cp "$PROXY_BIN" "$INSTALL_DIR/bin/safechain-proxy"
chmod 755 "$INSTALL_DIR/bin/safechain-ultimate"
chmod 755 "$INSTALL_DIR/bin/safechain-ultimate-ui"
chmod 755 "$INSTALL_DIR/bin/safechain-proxy"

# Copy scripts
echo "Copying scripts..."
mkdir -p "$INSTALL_DIR/scripts"
cp "$SCRIPT_DIR/scripts/uninstall" "$INSTALL_DIR/scripts/uninstall"
chmod 755 "$INSTALL_DIR/scripts/uninstall"

# Create app bundle for Login Items icon
echo "Creating app bundle..."
APP_BUNDLE_SRC="$SCRIPT_DIR/app-bundle"

# Copy Info.plist and update version
cp "$APP_BUNDLE_SRC/Contents/Info.plist" "$APP_BUNDLE_DIR/Contents/Info.plist"
sed -i '' "s/<string>1.0.0<\/string>/<string>$PKG_VERSION<\/string>/" "$APP_BUNDLE_DIR/Contents/Info.plist"

# Copy icon if it exists, otherwise generate it
ICNS_FILE="$APP_BUNDLE_SRC/Contents/Resources/AppIcon.icns"
if [ ! -f "$ICNS_FILE" ]; then
    echo "  Generating icns file..."
    "$SCRIPT_DIR/generate-icns.sh"
fi

if [ -f "$ICNS_FILE" ]; then
    cp "$ICNS_FILE" "$APP_BUNDLE_DIR/Contents/Resources/AppIcon.icns"
else
    echo "Warning: AppIcon.icns not found, Login Items will show generic icon" >&2
fi

# Copy LaunchDaemon plist
echo "Copying LaunchDaemon plist..."
cp "$SCRIPT_DIR/com.aikidosecurity.safechainultimate.plist" "$LAUNCHDAEMONS_DIR/"
chmod 644 "$LAUNCHDAEMONS_DIR/com.aikidosecurity.safechainultimate.plist"

# Copy scripts and set permissions
echo "Copying installer scripts..."
cp "$SCRIPT_DIR/scripts/preinstall" "$PKG_SCRIPTS/"
cp "$SCRIPT_DIR/scripts/postinstall" "$PKG_SCRIPTS/"
chmod 755 "$PKG_SCRIPTS/preinstall"
chmod 755 "$PKG_SCRIPTS/postinstall"

# Build the package
OUTPUT_PKG="$OUTPUT_DIR/SafeChainUltimate.$ARCH.pkg"
IDENTIFIER="com.aikidosecurity.safechainultimate"

echo "Building package..."
pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$PKG_SCRIPTS" \
    --identifier "$IDENTIFIER" \
    --version "$PKG_VERSION" \
    --install-location "/" \
    "$OUTPUT_PKG"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Package built successfully: $OUTPUT_PKG"
    echo ""
    
    # Calculate checksum
    CHECKSUM=$(shasum -a 256 "$OUTPUT_PKG" | awk '{print $1}')
    echo "SHA256: $CHECKSUM"
    echo "$CHECKSUM" > "$OUTPUT_PKG.sha256"
    echo ""
    
    # Display package info
    echo "Package information:"
    pkgutil --payload-files "$OUTPUT_PKG" | head -20
    echo ""
    
    # Display package size
    SIZE=$(du -h "$OUTPUT_PKG" | awk '{print $1}')
    echo "Package size: $SIZE"
else
    echo "Error: Package build failed" >&2
    exit 1
fi

exit 0
