#!/bin/bash

# =============================================================================
# SafeChain Ultimate - Local Installation Helper
# =============================================================================
# This script helps install the unsigned local PKG build
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PKG_FILE="$PROJECT_DIR/dist/SafeChainUltimate-dev-arm64.pkg"

echo "========================================="
echo "SafeChain Ultimate - Local Installation"
echo "========================================="
echo ""

# Check if PKG exists
if [ ! -f "$PKG_FILE" ]; then
    echo "Error: PKG file not found: $PKG_FILE"
    echo "Please run: packaging/macos/build-and-sign-local.sh"
    exit 1
fi

echo "Package: $PKG_FILE"
echo "Size: $(du -h "$PKG_FILE" | awk '{print $1}')"
echo ""

# Check signature status
echo "Checking package signature..."
if pkgutil --check-signature "$PKG_FILE" 2>&1 | grep -q "no signature"; then
    echo "⚠  Package is unsigned (expected for local builds)"
    echo ""
fi

# Install using sudo installer (bypasses Gatekeeper)
echo "Installing SafeChain Ultimate..."
echo "This will:"
echo "  - Install binaries to /Library/Application Support/AikidoSecurity/SafeChainUltimate/"
echo "  - Install LaunchDaemon to /Library/LaunchDaemons/"
echo "  - Start the agent service"
echo ""

read -p "Continue with installation? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

echo ""
sudo installer -pkg "$PKG_FILE" -target / -verbose

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================="
    echo "✓ Installation Complete!"
    echo "========================================="
    echo ""
    echo "The SafeChain Ultimate has been installed and started."
    echo ""
    echo "Service management:"
    echo "  Check status:  sudo launchctl list | grep safechainagent"
    echo "  Stop service:  sudo launchctl bootout system/com.aikidosecurity.safechainultimate"
    echo "  Start service: sudo launchctl bootstrap system /Library/LaunchDaemons/com.aikidosecurity.safechainultimate.plist"
    echo ""
    echo "View logs:"
    echo "  tail -f /Library/Logs/AikidoSecurity/SafeChainUltimate/safechain-ultimate.log"
    echo "  tail -f /Library/Logs/AikidoSecurity/SafeChainUltimate/safechain-ultimate.error.log"
    echo ""
    echo "To uninstall, run: packaging/macos/uninstall-local.sh"
    echo ""
else
    echo ""
    echo "✗ Installation failed"
    exit 1
fi
