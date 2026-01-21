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
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==================================="
echo "SafeChain Ultimate - Local PKG Builder"
echo "==================================="
echo "Version: $VERSION"
echo "Architecture: $ARCH"
echo ""

# =============================================================================
# Step 1: Build Binaries
# =============================================================================
echo "Step 1: Building binaries..."
echo ""

# Build Go agent
echo "Building safechain-ultimate..."
cd "$PROJECT_DIR"
go build -o "bin/safechain-ultimate-darwin-$ARCH" cmd/daemon/main.go
echo "✓ Agent built: bin/safechain-ultimate-darwin-$ARCH"

# Build Rust proxy
echo "Building safechain-proxy..."
cd "$PROJECT_DIR/proxy"
cargo build --release
cp "../target/release/safechain-proxy" "../bin/safechain-proxy-darwin-$ARCH"
cd "$PROJECT_DIR"
echo "✓ Proxy built: bin/safechain-proxy-darwin-$ARCH"
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
             "$PROJECT_DIR/bin/safechain-ultimate-darwin-$ARCH"
    echo "✓ Agent signed"
    
    codesign --sign "$CERT_IDENTITY" \
             --force \
             --timestamp \
             --options runtime \
             "$PROJECT_DIR/bin/safechain-proxy-darwin-$ARCH"
    echo "✓ Proxy signed"
    echo ""
    
    # Verify signatures
    echo "Verifying binary signatures..."
    codesign --verify --verbose "$PROJECT_DIR/bin/safechain-ultimate-darwin-$ARCH"
    codesign --verify --verbose "$PROJECT_DIR/bin/safechain-proxy-darwin-$ARCH"
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
./build-distribution-pkg.sh -v "$VERSION" -a "$ARCH" -b "$PROJECT_DIR/bin" -o "$PROJECT_DIR/dist"

PKG_FILE="$PROJECT_DIR/dist/SafeChainUltimate-$VERSION-$ARCH.pkg"

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
    SIGNED_PKG="$PROJECT_DIR/dist/SafeChainUltimate-$VERSION-$ARCH-signed.pkg"
    
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
