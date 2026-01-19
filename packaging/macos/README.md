# macOS Package Builder

This directory contains scripts and configuration files to build a macOS `.pkg` installer for SafeChain Agent.

## Files

- `build-pkg.sh` - Main build script that creates a basic `.pkg` installer
- `build-distribution-pkg.sh` - Enhanced build script that creates a distribution `.pkg` with installer UI
- `com.aikidosecurity.safechainagent.plist` - LaunchDaemon configuration
- `Distribution.xml` - Product distribution configuration for installer UI
- `welcome.html` - Welcome screen shown during installation
- `conclusion.html` - Conclusion screen shown after installation
- `license.txt` - Software license displayed during installation
- `scripts/` - Pre/post install scripts
  - `preinstall` - Runs before installation (stops existing daemon)
  - `postinstall` - Runs after installation (starts daemon, sets permissions)
  - `preuninstall` - Runs before uninstallation (stops daemon)

## Installation Layout

The installer will create the following structure:

```
/Library/Application Support/AikidoSecurity/SafeChainAgent/
└── bin/
    ├── safechain-agent
    └── safechain-proxy

/Library/LaunchDaemons/
└── com.aikidosecurity.safechainagent.plist

/Library/Logs/AikidoSecurity/SafeChainAgent/
├── .keep                    (placeholder, directory pre-created by installer)
├── safechain-agent.log      (created by daemon at runtime)
└── safechain-agent.error.log (created by daemon at runtime)
```

## Building the Package

### Prerequisites

- macOS with Xcode Command Line Tools installed
- Built binaries in the `bin` directory:
  - `safechain-agent-darwin-{arch}`
  - `safechain-proxy-darwin-{arch}`

### Basic Package (Component only)

```bash
./build-pkg.sh -v 1.0.0 -a arm64
```

This creates: `dist/SafeChainAgent.arm64.pkg`

### Distribution Package (With UI)

```bash
./build-distribution-pkg.sh -v 1.0.0 -a arm64
```

This creates: `dist/SafeChainAgent-1.0.0-arm64.pkg` with a polished installer UI.

### Options

Both scripts support the following options:

- `-v VERSION` - Version number (required, e.g., `1.0.0` or `dev`)
- `-a ARCH` - Architecture (required, `arm64` or `amd64`)
- `-b BIN_DIR` - Binary directory (optional, default: `./bin`)
- `-o OUTPUT_DIR` - Output directory (optional, default: `./dist`)
- `-h` - Show help

### Examples

```bash
# Build for Apple Silicon
./build-distribution-pkg.sh -v 1.0.0 -a arm64

# Build for Intel
./build-distribution-pkg.sh -v 1.0.0 -a amd64

# Build with custom binary directory
./build-pkg.sh -v 1.0.0 -a arm64 -b /path/to/binaries

# Build development version
./build-pkg.sh -v dev -a arm64
```

## Package Details

### LaunchDaemon Configuration

The package installs a LaunchDaemon that:
- Runs as root (`LocalSystem` equivalent)
- Starts automatically at boot (`RunAtLoad`)
- Keeps the agent running (`KeepAlive`)
- Logs to `/Library/Logs/AikidoSecurity/SafeChainAgent/`

### Installation Process

1. **Preinstall**: Stops existing daemon if running
2. **Install**: Copies binaries and LaunchDaemon plist
3. **Postinstall**: 
   - Creates log directory
   - Sets proper permissions (root:wheel)
   - Loads and starts the LaunchDaemon

### Uninstallation

The package does not include automatic uninstallation. To uninstall manually:

```bash
# Stop the daemon
sudo launchctl bootout system/com.aikidosecurity.safechainagent

# Remove files
sudo rm -rf "/Library/Application Support/AikidoSecurity/SafeChainAgent"
sudo rm -f /Library/LaunchDaemons/com.aikidosecurity.safechainagent.plist
sudo rm -rf /Library/Logs/AikidoSecurity/SafeChainAgent
```

## Managing the Service

```bash
# Check status
sudo launchctl list | grep safechainagent

# Stop the service
sudo launchctl bootout system/com.aikidosecurity.safechainagent

# Start the service
sudo launchctl bootstrap system /Library/LaunchDaemons/com.aikidosecurity.safechainagent.plist

# View logs
tail -f /Library/Logs/AikidoSecurity/SafeChainAgent/safechain-agent.log
tail -f /Library/Logs/AikidoSecurity/SafeChainAgent/safechain-agent.error.log
```

## Local Development Build

For local development and testing, you can use either the Makefile or direct scripts:

### Using Makefile (Recommended)

```bash
# From project root - build everything
make build-pkg-full

# Install the package
make install-pkg

# Uninstall when done testing
make uninstall-pkg
```

### Using Direct Scripts

```bash
# Build binaries, create PKG, and sign (if certificates available)
./build-and-sign-local.sh

# Install the package
./install-local.sh

# Uninstall when done testing
./uninstall-local.sh
```

See [LOCAL-BUILD.md](LOCAL-BUILD.md) for detailed local development instructions and [MAKEFILE-USAGE.md](MAKEFILE-USAGE.md) for Makefile target details.

## Signing and Notarization (Optional)

For distribution outside of GitHub releases, you may want to sign and notarize the package:

```bash
# Sign the package
productsign --sign "Developer ID Installer: Your Name" \
    SafeChainAgent-1.0.0-arm64.pkg \
    SafeChainAgent-1.0.0-arm64-signed.pkg

# Notarize (requires Apple Developer account)
xcrun notarytool submit SafeChainAgent-1.0.0-arm64-signed.pkg \
    --apple-id your@email.com \
    --team-id TEAMID \
    --password app-specific-password \
    --wait

# Staple the notarization
xcrun stapler staple SafeChainAgent-1.0.0-arm64-signed.pkg
```

## Troubleshooting

### Package won't install
- Check that you have admin privileges
- Verify the package signature: `pkgutil --check-signature SafeChainAgent-1.0.0-arm64.pkg`
- Check installer logs: `/var/log/install.log`

### Daemon won't start
- Check permissions: `ls -la "/Library/Application Support/AikidoSecurity/SafeChainAgent/bin/"`
- Check launchd logs: `sudo log show --predicate 'subsystem == "com.apple.launchd"' --last 1h`
- Verify plist syntax: `plutil -lint /Library/LaunchDaemons/com.aikidosecurity.safechainagent.plist`

### Binaries not found
- Ensure binaries are named correctly: `safechain-agent-darwin-{arch}` and `safechain-proxy-darwin-{arch}`
- Check that binaries are executable: `chmod +x bin/*`
