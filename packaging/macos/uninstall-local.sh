#!/bin/bash

# =============================================================================
# SafeChain Agent - Local Uninstallation Helper
# =============================================================================
# This script completely removes SafeChain Agent from the system
# =============================================================================

echo "========================================="
echo "SafeChain Agent - Uninstallation"
echo "========================================="
echo ""

echo "This will remove:"
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
echo "Stopping SafeChain Agent service..."
sudo launchctl bootout system/com.aikidosecurity.safechainagent 2>/dev/null || true
echo "✓ Service stopped"

echo ""
echo "Removing files..."
sudo rm -rf "/Library/Application Support/AikidoSecurity/SafeChainAgent"
echo "✓ Removed application files"

sudo rm -f /Library/LaunchDaemons/com.aikidosecurity.safechainagent.plist
echo "✓ Removed LaunchDaemon"

sudo rm -rf /Library/Logs/AikidoSecurity/SafeChainAgent
echo "✓ Removed log files"

echo ""
echo "========================================="
echo "✓ Uninstallation Complete!"
echo "========================================="
echo ""
