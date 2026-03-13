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

VERSION="${1:-dev}"
ARCH="universal"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==================================="
echo "SafeChain Ultimate - Local PKG Builder"
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

echo "Building safechain-ultimate for amd64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o "bin/safechain-ultimate-darwin-amd64" ./cmd/daemon
echo "Building safechain-ultimate for arm64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o "bin/safechain-ultimate-darwin-arm64" ./cmd/daemon

echo "Creating universal agent binary with lipo..."
lipo -create bin/safechain-ultimate-darwin-amd64 bin/safechain-ultimate-darwin-arm64 \
    -output bin/safechain-ultimate-darwin-universal
echo "✓ Agent built: bin/safechain-ultimate-darwin-universal"
# clean up any stale UI artifacts before building fresh app bundles
rm -rf "$PROJECT_DIR/ui/bin/"
rm -rf "$PROJECT_DIR/bin/safechain-ultimate-ui-darwin-amd64.app"
rm -rf "$PROJECT_DIR/bin/safechain-ultimate-ui-darwin-arm64.app"

# check if wails3 is installed
if ! command -v wails3 &> /dev/null; then
    echo "wails3 could not be found. Please install it using:"
    echo "   go install github.com/wailsapp/wails/v3/cmd/wails3@latest"
    echo "Then run this script again (for more details, see https://v3alpha.wails.io/quick-start/installation/)."
    exit 1
fi

echo "Building safechain-ultimate-ui (Wails app bundle) for amd64..."
cd "$PROJECT_DIR/ui"
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 wails3 package 
mv "$PROJECT_DIR/ui/bin/safechain-ultimate-ui.app" "$PROJECT_DIR/bin/safechain-ultimate-ui-darwin-amd64.app"
rm -rf "$PROJECT_DIR/ui/bin/"

echo "Building safechain-ultimate-ui (Wails app bundle) for arm64..."
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 wails3 package
mv "$PROJECT_DIR/ui/bin/safechain-ultimate-ui.app" "$PROJECT_DIR/bin/safechain-ultimate-ui-darwin-arm64.app"

cd "$PROJECT_DIR"
echo "Creating universal UI app bundle with lipo..."
APP_BINARY_NAME="safechain-ultimate-ui"
cp -R "bin/safechain-ultimate-ui-darwin-amd64.app" "bin/safechain-ultimate-ui-darwin-universal.app"
lipo -create \
    "bin/safechain-ultimate-ui-darwin-amd64.app/Contents/MacOS/$APP_BINARY_NAME" \
    "bin/safechain-ultimate-ui-darwin-arm64.app/Contents/MacOS/$APP_BINARY_NAME" \
    -output "bin/safechain-ultimate-ui-darwin-universal.app/Contents/MacOS/$APP_BINARY_NAME"
echo "✓ Agent UI built: bin/safechain-ultimate-ui-darwin-universal.app"

echo "Building safechain-l7-proxy for x86_64-apple-darwin..."
rustup target add x86_64-apple-darwin 2>/dev/null || true
cargo build --release --bin safechain-l7-proxy --target x86_64-apple-darwin

echo "Building safechain-l7-proxy for aarch64-apple-darwin..."
rustup target add aarch64-apple-darwin 2>/dev/null || true
cargo build --release --bin safechain-l7-proxy --target aarch64-apple-darwin

echo "Creating universal proxy binary with lipo..."
lipo -create \
    target/x86_64-apple-darwin/release/safechain-l7-proxy \
    target/aarch64-apple-darwin/release/safechain-l7-proxy \
    -output bin/safechain-l7-proxy-darwin-universal
echo "✓ Proxy built: bin/safechain-l7-proxy-darwin-universal"

lipo -info bin/safechain-ultimate-darwin-universal
lipo -info "bin/safechain-ultimate-ui-darwin-universal.app/Contents/MacOS/$APP_BINARY_NAME"
lipo -info bin/safechain-l7-proxy-darwin-universal
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
             "$PROJECT_DIR/bin/safechain-ultimate-darwin-universal"
    echo "✓ Agent signed"

    codesign --sign "$CERT_IDENTITY" \
             --force \
             --deep \
             --timestamp \
             --options runtime \
             "$PROJECT_DIR/bin/safechain-ultimate-ui-darwin-universal.app"
    echo "✓ Agent UI signed"

    codesign --sign "$CERT_IDENTITY" \
             --force \
             --timestamp \
             --options runtime \
             "$PROJECT_DIR/bin/safechain-l7-proxy-darwin-universal"
    echo "✓ Proxy signed"
    echo ""

    echo "Verifying binary signatures..."
    codesign --verify --verbose "$PROJECT_DIR/bin/safechain-ultimate-darwin-universal"
    codesign --verify --verbose "$PROJECT_DIR/bin/safechain-ultimate-ui-darwin-universal.app"
    codesign --verify --verbose "$PROJECT_DIR/bin/safechain-l7-proxy-darwin-universal"
    echo "✓ Binary signatures verified"
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

PKG_FILE="$PROJECT_DIR/dist/SafeChainUltimate-$VERSION.pkg"

if [ ! -f "$PKG_FILE" ]; then
    echo "✗ PKG file not created"
    exit 1
fi

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
    SIGNED_PKG="$PROJECT_DIR/dist/SafeChainUltimate-$VERSION-signed.pkg"

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
