#!/bin/bash

set -e

# Build macOS .pkg installer for Aikido Endpoint Protection
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

echo "Building macOS .pkg installer for Aikido Endpoint Protection v$VERSION"
echo "  Architecture: $ARCH"
echo "  Binary directory: $BIN_DIR"
echo "  Output directory: $OUTPUT_DIR"
echo "  Project directory: $PROJECT_DIR"

# Verify binaries exist
AGENT_BIN="$BIN_DIR/endpoint-protection-darwin-$ARCH"
AGENT_UI_APP="$BIN_DIR/endpoint-protection-ui-darwin-$ARCH.app"
PROXY_BIN="$BIN_DIR/safechain-l7-proxy-darwin-$ARCH"
L4_PROXY_APP="$BIN_DIR/Aikido Network Extension.app"

if [ ! -f "$AGENT_BIN" ]; then
    echo "Error: endpoint-protection binary not found at $AGENT_BIN" >&2
    exit 1
fi

if [ ! -d "$AGENT_UI_APP" ]; then
    echo "Error: endpoint-protection-ui app not found at $AGENT_UI_APP" >&2
    exit 1
fi

if [ ! -f "$PROXY_BIN" ]; then
    echo "Error: safechain-l7-proxy binary not found at $PROXY_BIN" >&2
    exit 1
fi

if [ ! -d "$L4_PROXY_APP" ]; then
    echo "Error: L4 proxy app not found at $L4_PROXY_APP" >&2
    exit 1
fi

# Create temporary build directory
BUILD_DIR="$(mktemp -d)"
trap "rm -rf '$BUILD_DIR'" EXIT

echo "Using temporary build directory: $BUILD_DIR"

# Create package directory structure
PKG_ROOT="$BUILD_DIR/pkg_root"
PKG_SCRIPTS="$BUILD_DIR/scripts"
APPS_INSTALL_DIR="$PKG_ROOT/Applications"
EP_APP_DIR="$APPS_INSTALL_DIR/Aikido Endpoint Protection.app"
SUPPORT_DIR="$PKG_ROOT/Library/Application Support/AikidoSecurity/EndpointProtection"
LAUNCHDAEMONS_DIR="$PKG_ROOT/Library/LaunchDaemons"
LOGS_DIR="$PKG_ROOT/Library/Logs/AikidoSecurity/EndpointProtection"

mkdir -p "$APPS_INSTALL_DIR"
mkdir -p "$SUPPORT_DIR"
mkdir -p "$LAUNCHDAEMONS_DIR"
mkdir -p "$LOGS_DIR"
mkdir -p "$PKG_SCRIPTS"

# Create placeholder file in logs directory to ensure it's included in package
touch "$LOGS_DIR/.keep"
chmod 644 "$LOGS_DIR/.keep"

# Copy the UI app bundle as the main Aikido Endpoint Protection app
echo "Copying Aikido Endpoint Protection app bundle..."
cp -R "$AGENT_UI_APP" "$EP_APP_DIR"

# Embed daemon binary and L7 proxy inside the app bundle
echo "Embedding binaries into app bundle..."
mkdir -p "$EP_APP_DIR/Contents/Resources/bin"
cp "$AGENT_BIN" "$EP_APP_DIR/Contents/Resources/bin/endpoint-protection"
cp "$PROXY_BIN" "$EP_APP_DIR/Contents/Resources/bin/safechain-l7-proxy"
chmod 755 "$EP_APP_DIR/Contents/Resources/bin/endpoint-protection"
chmod 755 "$EP_APP_DIR/Contents/Resources/bin/safechain-l7-proxy"

# Embed uninstall script into the app bundle
echo "Embedding scripts into app bundle..."
mkdir -p "$EP_APP_DIR/Contents/Resources/scripts"
cp "$SCRIPT_DIR/scripts/uninstall" "$EP_APP_DIR/Contents/Resources/scripts/uninstall"
chmod 755 "$EP_APP_DIR/Contents/Resources/scripts/uninstall"

echo "Re-signing Aikido Endpoint Protection app bundle..."
if [ -n "$CODESIGN_IDENTITY" ]; then
    SIGN_ARGS=(--force --deep --sign "$CODESIGN_IDENTITY" --timestamp --options runtime)
    if [ -n "$KEYCHAIN_PATH" ]; then
        SIGN_ARGS+=(--keychain "$KEYCHAIN_PATH")
    fi
    codesign "${SIGN_ARGS[@]}" "$EP_APP_DIR"
else
    codesign --force --deep --sign - "$EP_APP_DIR"
fi

echo "Copying Aikido Network Extension app bundle..."
ditto "$L4_PROXY_APP" "$APPS_INSTALL_DIR/Aikido Network Extension.app"
chmod 755 "$APPS_INSTALL_DIR/Aikido Network Extension.app/Contents/MacOS/Aikido Network Extension"
L4_SYSEXT_DIR="$APPS_INSTALL_DIR/Aikido Network Extension.app/Contents/Library/SystemExtensions"
L4_SYSEXT=$(find "$L4_SYSEXT_DIR" -maxdepth 1 -name "*.systemextension" | head -1)
if [ -n "$L4_SYSEXT" ]; then
    L4_SYSEXT_NAME=$(basename "$L4_SYSEXT" .systemextension)
    chmod 755 "$L4_SYSEXT/Contents/MacOS/$L4_SYSEXT_NAME"
else
    echo "Warning: No system extension found in $L4_SYSEXT_DIR"
fi

# Copy LaunchDaemon plist
echo "Copying LaunchDaemon plist..."
cp "$SCRIPT_DIR/com.aikidosecurity.endpointprotection.plist" "$LAUNCHDAEMONS_DIR/"
chmod 644 "$LAUNCHDAEMONS_DIR/com.aikidosecurity.endpointprotection.plist"

# Copy scripts and set permissions
echo "Copying installer scripts..."
cp "$SCRIPT_DIR/scripts/preinstall" "$PKG_SCRIPTS/"
cp "$SCRIPT_DIR/scripts/postinstall" "$PKG_SCRIPTS/"
chmod 755 "$PKG_SCRIPTS/preinstall"
chmod 755 "$PKG_SCRIPTS/postinstall"

# Build the package
OUTPUT_PKG="$OUTPUT_DIR/EndpointProtection.pkg"
IDENTIFIER="com.aikidosecurity.endpointprotection"

COMPONENT_PLIST="$BUILD_DIR/component.plist"

pkgbuild --analyze --root "$PKG_ROOT" "$COMPONENT_PLIST"
if /usr/libexec/PlistBuddy -c "Print" "$COMPONENT_PLIST" >/dev/null 2>&1; then
    IDX=0
    while /usr/libexec/PlistBuddy -c "Print :${IDX}" "$COMPONENT_PLIST" >/dev/null 2>&1; do
        /usr/libexec/PlistBuddy -c "Set :${IDX}:BundleHasStrictIdentifier false" "$COMPONENT_PLIST" 2>/dev/null || true
        /usr/libexec/PlistBuddy -c "Set :${IDX}:BundleIsRelocatable false" "$COMPONENT_PLIST" 2>/dev/null || true
        /usr/libexec/PlistBuddy -c "Set :${IDX}:BundleIsVersionChecked false" "$COMPONENT_PLIST" 2>/dev/null || true
        # Drop ChildBundles so PackageInfo / Distribution only advertise the
        # top-level apps to MDM systems (Intune rejects packages that expose
        # internal Swift resource bundles or system extensions as installable
        # bundles). The payload is unaffected.
        /usr/libexec/PlistBuddy -c "Delete :${IDX}:ChildBundles" "$COMPONENT_PLIST" 2>/dev/null || true
        IDX=$((IDX + 1))
    done
    echo "Configured $IDX bundle entries in component plist (no child bundles, non-relocatable)"
fi

echo "Building package..."
pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$PKG_SCRIPTS" \
    --component-plist "$COMPONENT_PLIST" \
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
