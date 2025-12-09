#!/bin/bash
set -e

# Installation script for sc-agent daemon

BINARY_NAME="sc-agent"
INSTALL_DIR="/usr/local/bin"
PLIST_NAME="homebrew.mxcl.sc-agent.plist"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/$PLIST_NAME"
LOG_DIR="/usr/local/var/log"

echo "Installing $BINARY_NAME daemon..."

# Check if binary exists
if [ ! -f "./bin/$BINARY_NAME" ]; then
    echo "Error: Binary not found at ./bin/$BINARY_NAME"
    echo "Please build the binary first with: make build"
    exit 1
fi

# Install binary
echo "Installing binary to $INSTALL_DIR..."
sudo cp "./bin/$BINARY_NAME" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Create log directory
echo "Creating log directory..."
sudo mkdir -p "$LOG_DIR"
sudo chmod 755 "$LOG_DIR"

# Create plist file
echo "Creating LaunchAgent plist..."
mkdir -p "$PLIST_DIR"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_NAME</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/$BINARY_NAME</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/$BINARY_NAME.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/$BINARY_NAME.error.log</string>
</dict>
</plist>
EOF

echo "Installation complete!"
echo ""
echo "To start the daemon:"
echo "  launchctl load $PLIST_PATH"
echo ""
echo "To stop the daemon:"
echo "  launchctl unload $PLIST_PATH"
echo ""
echo "To check daemon status:"
echo "  launchctl list | grep $BINARY_NAME"
echo ""
echo "Logs are available at:"
echo "  $LOG_DIR/$BINARY_NAME.log"
echo "  $LOG_DIR/$BINARY_NAME.error.log"

