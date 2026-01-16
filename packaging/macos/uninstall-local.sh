#!/bin/bash

# =============================================================================
# SafeChain Agent - Local Uninstallation Helper
# =============================================================================
# This script completely removes SafeChain Agent from the system
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREUNINSTALL_SCRIPT="$SCRIPT_DIR/scripts/preuninstall"

echo "========================================="
echo "SafeChain Agent - Uninstallation"
echo "========================================="
echo ""

echo "This will remove:"
echo "  - Stop and unload the SafeChain Agent daemon"
echo "  - Run SafeChain Agent teardown"
echo "  - /Library/Application Support/AikidoSecurity/SafeChainAgent/"
echo "  - /Library/LaunchDaemons/com.aikidosecurity.safechainagent.plist"
echo "  - /Library/Logs/AikidoSecurity/SafeChainAgent/"
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
sudo rm -rf "/Library/Application Support/AikidoSecurity/SafeChainAgent"
echo "✓ Removed application files"

sudo rm -rf /Library/Logs/AikidoSecurity/SafeChainAgent
echo "✓ Removed log files"

echo ""
echo "========================================="
echo "✓ Uninstallation Complete!"
echo "========================================="
echo ""
