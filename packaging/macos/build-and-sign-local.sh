#!/bin/bash
set -e

# =============================================================================
# Local macOS PKG Builder with Code Signing
# =============================================================================
# This script builds binaries, signs them, creates a PKG, and signs the PKG
# for local installation without macOS security warnings.
#
# Usage: ./build-and-sign-local.sh
# =============================================================================

ARCH="universal"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-dev}"

if [ "$VERSION" = "--generate-version" ]; then
  VERSION="0.0.$(date +%s)"
  bash "$PROJECT_DIR/scripts/sync-versions.sh" --version "$VERSION"
  restore_versions() {
    bash "$PROJECT_DIR/scripts/sync-versions.sh" --version "1.0.0"
  }
  trap restore_versions EXIT
fi

echo "==================================="
echo "Aikido Endpoint Protection - Local PKG Builder"
echo "==================================="
echo "Version: $VERSION"
echo "Architecture: $ARCH (x86_64 + arm64)"
echo ""

# =============================================================================
# Step 1: Build Binaries
# =============================================================================
echo "Step 1: Building universal binaries..."
echo ""

cd "$PROJECT_DIR"
mkdir -p bin

echo "Building endpoint-protection for amd64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o "bin/endpoint-protection-darwin-amd64" ./cmd/daemon
echo "Building endpoint-protection for arm64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "bin/endpoint-protection-darwin-arm64" ./cmd/daemon

echo "Creating universal agent binary with lipo..."
lipo -create bin/endpoint-protection-darwin-amd64 bin/endpoint-protection-darwin-arm64 \
    -output bin/endpoint-protection-darwin-universal
echo "✓ Agent built: bin/endpoint-protection-darwin-universal"
# clean up any stale UI artifacts before building fresh app bundles
rm -rf "$PROJECT_DIR/ui/bin/"
rm -rf "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-amd64.app"
rm -rf "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-arm64.app"
rm -rf "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-universal.app"

# check if wails3 is installed
if ! command -v wails3 &> /dev/null; then
    echo "wails3 could not be found. Please install it using:"
    echo "   go install github.com/wailsapp/wails/v3/cmd/wails3@latest"
    echo "Then run this script again (for more details, see https://v3alpha.wails.io/quick-start/installation/)."
    exit 1
fi

echo "Building endpoint-protection-ui (Wails app bundle) for amd64..."
cd "$PROJECT_DIR/ui"
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 wails3 package 
mv "$PROJECT_DIR/ui/bin/endpoint-protection-ui.app" "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-amd64.app"
rm -rf "$PROJECT_DIR/ui/bin/"

echo "Building endpoint-protection-ui (Wails app bundle) for arm64..."
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 wails3 package
mv "$PROJECT_DIR/ui/bin/endpoint-protection-ui.app" "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-arm64.app"

cd "$PROJECT_DIR"
echo "Creating universal UI app bundle with lipo..."
APP_BINARY_NAME="endpoint-protection-ui"
cp -R "bin/endpoint-protection-ui-darwin-amd64.app" "bin/endpoint-protection-ui-darwin-universal.app"
lipo -create \
    "bin/endpoint-protection-ui-darwin-amd64.app/Contents/MacOS/$APP_BINARY_NAME" \
    "bin/endpoint-protection-ui-darwin-arm64.app/Contents/MacOS/$APP_BINARY_NAME" \
    -output "bin/endpoint-protection-ui-darwin-universal.app/Contents/MacOS/$APP_BINARY_NAME"
echo "✓ Agent UI built: bin/endpoint-protection-ui-darwin-universal.app"

if ! command -v xcodegen &> /dev/null; then
    echo "xcodegen could not be found. Please install it using:"
    echo "   brew install xcodegen"
    echo "Then run this script again."
    exit 1
fi

echo "Building L4 proxy Rust static library for x86_64-apple-darwin..."
cargo build --release -p safechain-lib-l4-proxy-macos --target x86_64-apple-darwin

echo "Building L4 proxy Rust static library for aarch64-apple-darwin..."
cargo build --release -p safechain-lib-l4-proxy-macos --target aarch64-apple-darwin

echo "Creating universal L4 proxy static library with lipo..."
mkdir -p target/universal
lipo -create \
    target/x86_64-apple-darwin/release/libsafechain_lib_l4_proxy_macos.a \
    target/aarch64-apple-darwin/release/libsafechain_lib_l4_proxy_macos.a \
    -output target/universal/libsafechain_lib_l4_proxy_macos.a
echo "✓ L4 proxy static library built"

echo "Generating L4 proxy Xcode project..."
cd "$PROJECT_DIR/packaging/macos/xcode/l4-proxy"
xcodegen generate --spec Project.dev.yml

L4_DERIVED_DATA="$PROJECT_DIR/.aikido/xcode/safechain-l4-proxy-release"

echo "Building L4 proxy macOS app..."
xcodebuild \
    -project AikidoNetworkExtension.xcodeproj \
    -scheme AikidoNetworkExtensionHost \
    -configuration Release \
    -derivedDataPath "$L4_DERIVED_DATA" \
    -allowProvisioningUpdates \
    -allowProvisioningDeviceRegistration \
    clean build

cd "$PROJECT_DIR"

L4_APP_SRC="$L4_DERIVED_DATA/Build/Products/Release/Aikido Network Extension.app"
if [ ! -d "$L4_APP_SRC" ]; then
    echo "✗ L4 proxy app build failed — app bundle not found at $L4_APP_SRC"
    exit 1
fi

rm -rf "bin/Aikido Network Extension.app"
ditto "$L4_APP_SRC" "bin/Aikido Network Extension.app"
echo "✓ L4 Network Extension app built: bin/Aikido Network Extension.app"

lipo -info bin/endpoint-protection-darwin-universal
lipo -info "bin/endpoint-protection-ui-darwin-universal.app/Contents/MacOS/$APP_BINARY_NAME"
echo ""

# =============================================================================
# Step 2: Sign Binaries (if certificates available)
# =============================================================================
echo "Step 2: Checking for signing certificates..."
echo ""

echo "Checking for signing certificates..."
security find-identity -v -p codesigning
echo ""

# Check if we have a Developer ID Application certificate
if security find-identity -v -p codesigning | grep "Developer ID Application" > /dev/null; then
    echo "✓ Found Developer ID Application certificate"

    # Get the certificate identity
    CERT_IDENTITY=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -1 | awk -F'"' '{print $2}')
    echo "  Using: $CERT_IDENTITY"
    echo ""

    echo "Signing binaries..."
    codesign --sign "$CERT_IDENTITY" \
             --force \
             --timestamp \
             --options runtime \
             "$PROJECT_DIR/bin/endpoint-protection-darwin-universal"
    echo "✓ Agent signed"

    codesign --sign "$CERT_IDENTITY" \
             --force \
             --deep \
             --timestamp \
             --options runtime \
             "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-universal.app"
    echo "✓ Agent UI signed"

    echo "Verifying binary signatures..."
    codesign --verify --verbose "$PROJECT_DIR/bin/endpoint-protection-darwin-universal"
    codesign --verify --verbose "$PROJECT_DIR/bin/endpoint-protection-ui-darwin-universal.app"
    echo "✓ Binary signatures verified"

    echo "Verifying L4 proxy app signature (signed by Xcode)..."
    codesign --verify --verbose --deep "$PROJECT_DIR/bin/Aikido Network Extension.app"
    echo "✓ L4 Proxy app signature verified"
    echo ""
else
    echo "⚠ No Developer ID Application certificate found"
    echo "  Binaries will not be signed - macOS will show security warnings"
    echo "  To sign binaries, you need a Developer ID certificate from Apple"
    echo ""
fi

# =============================================================================
# Step 3: Build PKG
# =============================================================================
echo "Step 3: Building PKG installer..."
echo ""

cd "$SCRIPT_DIR"
./build-distribution-pkg.sh -v "$VERSION" -a "universal" -b "$PROJECT_DIR/bin" -o "$PROJECT_DIR/dist"

VERSIONED_PKG="$PROJECT_DIR/dist/EndpointProtection-$VERSION.pkg"

if [ ! -f "$VERSIONED_PKG" ]; then
    echo "✗ PKG file not created"
    exit 1
fi

PKG_FILE="$PROJECT_DIR/dist/EndpointProtection.pkg"
mv "$VERSIONED_PKG" "$PKG_FILE"
rm -f "$VERSIONED_PKG.sha256"
echo "✓ PKG created: $PKG_FILE"
echo ""

# =============================================================================
# Step 4: Sign PKG (if certificates available)
# =============================================================================
echo "Step 4: Checking for PKG signing certificates..."
echo ""

# Check if we have a Developer ID Installer certificate
if security find-identity -v -p basic | grep "Developer ID Installer" > /dev/null; then
    echo "✓ Found Developer ID Installer certificate"

    # Get the certificate identity
    INSTALLER_CERT_IDENTITY=$(security find-identity -v -p basic | grep "Developer ID Installer" | head -1 | awk -F'"' '{print $2}')
    echo "  Using: $INSTALLER_CERT_IDENTITY"
    echo ""

    echo "Signing PKG..."
    SIGNED_PKG="$PROJECT_DIR/dist/EndpointProtection-$VERSION-signed.pkg"

    productsign --sign "$INSTALLER_CERT_IDENTITY" \
                --timestamp \
                "$PKG_FILE" \
                "$SIGNED_PKG"

    # Replace unsigned with signed
    mv "$SIGNED_PKG" "$PKG_FILE"

    echo "✓ PKG signed"
    echo ""

    # Verify signature
    echo "Verifying PKG signature..."
    pkgutil --check-signature "$PKG_FILE"
    echo "✓ PKG signature verified"
    echo ""
else
    echo "⚠ No Developer ID Installer certificate found"
    echo "  PKG will not be signed - macOS may show security warnings"
    echo "  To sign the PKG, you need a Developer ID Installer certificate from Apple"
    echo ""
fi

# =============================================================================
# Summary
# =============================================================================
echo "==================================="
echo "Build Complete!"
echo "==================================="
echo ""
echo "Package: $PKG_FILE"
echo "Size: $(du -h "$PKG_FILE" | awk '{print $1}')"
echo "SHA256: $(shasum -a 256 "$PKG_FILE" | awk '{print $1}')"
echo ""
echo "To install:"
echo "  cd $PROJECT_DIR"
echo "  ./packaging/macos/install-local.sh"
echo ""
echo "Or use:"
echo "  sudo installer -pkg $PKG_FILE -target /"
echo ""

# Check signing status
if pkgutil --check-signature "$PKG_FILE" 2>/dev/null | grep -q "Status: signed"; then
    echo "✓ Package is signed and should install without security warnings"
else
    echo "⚠ Package is not signed"
    echo "  You may need to right-click and select 'Open' to install"
    echo "  Or allow it in System Settings > Privacy & Security"
fi
echo ""
