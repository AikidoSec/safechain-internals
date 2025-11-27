#!/bin/bash
set -e

# Uninstallation script for safechain-agent daemon

BINARY_NAME="safechain-agent"
INSTALL_DIR="/usr/local/bin"
PLIST_NAME="homebrew.mxcl.safechain-agent.plist"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/$PLIST_NAME"
LOG_DIR="/usr/local/var/log"

echo "Uninstalling $BINARY_NAME daemon..."

# Stop and unload daemon if running
if [ -f "$PLIST_PATH" ]; then
    echo "Stopping daemon..."
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"
    echo "Removed LaunchAgent plist"
fi

# Remove binary
if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo "Removing binary..."
    sudo rm -f "$INSTALL_DIR/$BINARY_NAME"
    echo "Removed binary"
fi

# Optionally remove logs (commented out by default)
# echo "Removing log files..."
# sudo rm -f "$LOG_DIR/$BINARY_NAME.log"
# sudo rm -f "$LOG_DIR/$BINARY_NAME.error.log"

echo "Uninstallation complete!"

