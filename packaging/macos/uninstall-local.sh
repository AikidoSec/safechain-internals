#!/bin/bash

# =============================================================================
# SafeChain Ultimate - Local Uninstallation Helper
# =============================================================================
# This script completely removes SafeChain Ultimate from the system
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREUNINSTALL_SCRIPT="$SCRIPT_DIR/scripts/preuninstall"

echo "========================================="
echo "SafeChain Ultimate - Uninstallation"
echo "========================================="
echo ""

echo "This will remove:"
echo "  - Stop and unload the SafeChain Ultimate daemon"
echo "  - Run SafeChain Ultimate teardown"
echo "  - /Library/Application Support/AikidoSecurity/SafeChainUltimate/"
echo "  - /Library/LaunchDaemons/com.aikidosecurity.safechainultimate.plist"
echo "  - /Library/Logs/AikidoSecurity/SafeChainUltimate/"
echo ""

read -p "Continue with uninstallation? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled"
    exit 0
fi

echo ""

# Run preuninstall script (stops daemon and runs teardown)
if [ -f "$PREUNINSTALL_SCRIPT" ]; then
    echo "Running pre-uninstall script..."
    sudo "$PREUNINSTALL_SCRIPT"
    echo ""
else
    echo "Warning: preuninstall script not found at $PREUNINSTALL_SCRIPT"
fi

echo "Removing files..."
sudo rm -rf "/Library/Application Support/AikidoSecurity/SafeChainUltimate"
echo "✓ Removed application files"

sudo rm -rf /Library/Logs/AikidoSecurity/SafeChainUltimate
echo "✓ Removed log files"

echo ""
echo "========================================="
echo "✓ Uninstallation Complete!"
echo "========================================="
echo ""
