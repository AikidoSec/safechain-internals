# Safechain-agent

A daemon service that runs continuously on macOS, packaged as a Homebrew formula.

## Project Structure

```
.
├── cmd/
│   └── daemon/          # Main application entry point
├── internal/
│   ├── daemon/          # Internal daemon implementation
│   ├── scanner/         # Scanner interface and implementations
│   │   ├── safechain/   # Safechain scanner implementation
│   │   ├── githook/     # Git hook scanner implementation
│   │   └── vscode/      # VSCode scanner implementation
│   ├── scannermanager/  # Scanner registry and management
│   └── version/         # Version information package
├── build/
│   └── Formula/         # Homebrew formula
├── scripts/             # Installation and build scripts
├── Makefile            # Build automation
└── go.mod              # Go module definition
```

## Building

### Prerequisites

- Go 1.19 or later
- Make

### Build the daemon

```bash
# Build binary
make build

# Build release binary (optimized)
make build-release

# Run locally
make run
```

## Installation

### Manual Installation

```bash
# Build the binary
make build

# Run the install script
./scripts/install.sh
```

### Homebrew Installation

#### Building the Homebrew Formula

##### Local Build

To build the complete Homebrew formula (including binaries for both architectures and updating checksums):

```bash
# Using the script directly
./scripts/build-brew-formula.sh

# Or using make
make brew-formula

# With a specific version
VERSION=1.0.0 ./scripts/build-brew-formula.sh
```

This script will:
- Build binaries for both `darwin/amd64` and `darwin/arm64`
- Create tarballs for each architecture
- Calculate SHA256 checksums
- Update the formula file with checksums and version

##### Automated Build via GitHub Actions

The project includes a GitHub Actions workflow that automatically builds the Homebrew formula when you push a version tag:

1. **Create and push a version tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **The workflow will automatically:**
   - Build binaries for both `darwin/amd64` and `darwin/arm64`
   - Create tarballs and calculate checksums
   - Update the formula file with the correct checksums
   - Create a GitHub Release with the tarballs attached
   - Upload artifacts for download

The workflow is defined in `.github/workflows/build-brew-formula.yml` and triggers on tags matching `v*` (e.g., `v1.0.0`, `v2.1.3`).

#### Installing the Homebrew Formula

To install the formula after building:

```bash
# Using the install script (recommended)
./scripts/install-brew-formula.sh

# Or using make (builds and installs in one step)
make brew-install

# Or manually using brew
brew install --build-from-source build/Formula/safechain-agent.rb
```

The install script will:
- Check if Homebrew is installed
- Verify the formula file exists
- Check if already installed and offer to reinstall
- Install the formula using `brew install`
- Show post-installation instructions

#### Installing from a Tap (once published)

```bash
brew install aikido/safechain-agent/safechain-agent
```

## Daemon Management

### Start the daemon

```bash
launchctl load ~/Library/LaunchAgents/homebrew.mxcl.safechain-agent.plist
```

### Stop the daemon

```bash
launchctl unload ~/Library/LaunchAgents/homebrew.mxcl.safechain-agent.plist
```

### Check daemon status

```bash
launchctl list | grep safechain-agent
```

### View logs

```bash
# Standard output
tail -f /usr/local/var/log/safechain-agent.log

# Error output
tail -f /usr/local/var/log/safechain-agent.error.log
```

## Uninstallation

```bash
./scripts/uninstall.sh
```

Or if installed via Homebrew:

```bash
brew uninstall safechain-agent
```

## Development

### Run tests

```bash
make test
```

### Clean build artifacts

```bash
make clean
```

## Scanner System

The project includes a pluggable scanner system for different protection engines. Each scanner implements the `Scanner` interface with the following methods:

- `Name()` - Returns the scanner name
- `Install(ctx)` - Installs the protection engine
- `Uninstall(ctx)` - Removes the protection engine
- `IsInstalled(ctx)` - Checks if the scanner is installed

### Available Scanners

1. **Safechain** (`internal/scanner/safechain/`) - Safechain protection engine
2. **GitHook** (`internal/scanner/githook/`) - Git hook-based protection
3. **VSCode** (`internal/scanner/vscode/`) - VSCode extension protection

### Using the Scanner Registry

The `scannermanager` package provides a registry to manage all scanners:

```go
import "github.com/aikido/safechain-agent/internal/scannermanager"

// Create a new registry (automatically registers all scanners)
registry := scannermanager.NewRegistry()

// Get a specific scanner
scanner, err := registry.Get("safechain")

// Install all scanners
err := registry.InstallAll(ctx)

// List all available scanners
scanners := registry.List()
```

## Configuration

The daemon accepts the following command-line flags:

- `--config`: Path to configuration file (optional)
- `--log-level`: Log level (debug, info, warn, error), default: info
- `--version`: Show version information

## License

MIT
