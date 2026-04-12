#!/bin/bash

# =============================================================================
# Aikido Endpoint Protection - Local Installation Helper
# =============================================================================
# This script helps install the unsigned local PKG build
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PKG_FILE="$PROJECT_DIR/dist/EndpointProtection.pkg"

echo "========================================="
echo "Aikido Endpoint Protection - Local Installation"
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
echo "Installing Aikido Endpoint Protection..."
echo "This will:"
echo "  - Install apps to /Applications/ (Aikido Endpoint Protection, Aikido Network Extension)"
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
    echo "Aikido Endpoint Protection has been installed and started."
    echo ""
    echo "Service management:"
    echo "  Check status:  sudo launchctl list | grep endpointprotection"
    echo "  Stop service:  sudo launchctl bootout system/com.aikidosecurity.endpointprotection"
    echo "  Start service: sudo launchctl bootstrap system /Library/LaunchDaemons/com.aikidosecurity.endpointprotection.plist"
    echo ""
    echo "View logs:"
    echo "  tail -f /Library/Logs/AikidoSecurity/EndpointProtection/endpoint-protection.log"
    echo "  tail -f /Library/Logs/AikidoSecurity/EndpointProtection/endpoint-protection.err"
    echo ""
    echo "To uninstall, run: sudo \"/Applications/Aikido Endpoint Protection.app/Contents/Resources/scripts/uninstall\""
    echo ""
else
    echo ""
    echo "✗ Installation failed"
    exit 1
fi
