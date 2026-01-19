# Linux RPM Package Builder

This directory contains scripts and configuration files to build an RPM package for SafeChain Agent.

## Files

- `build-rpm.sh` - Main build script that creates an RPM package
- `safechain-agent.spec` - RPM spec file defining package contents and installation
- `safechain-agent.service` - systemd service unit file

## Installation Layout

The installer will create the following structure:

```
/opt/aikidosecurity/safechainagent/
└── bin/
    ├── safechain-agent
    └── safechain-proxy

/var/log/aikidosecurity/safechainagent/
├── safechain-agent.log       (created by service at runtime)
└── safechain-agent.error.log (created by service at runtime)

/var/run/aikidosecurity/safechainagent/
└── (runtime files)

/etc/systemd/system/
└── safechain-agent.service
```

## Building the Package

### Prerequisites

- Linux with `rpmbuild` installed (from `rpm-build` package)
- Built binaries in the `bin` directory:
  - `safechain-agent-linux-{arch}`
  - `safechain-proxy-linux-{arch}`

Install prerequisites on Fedora/RHEL/CentOS:
```bash
sudo dnf install rpm-build
```

### Building

```bash
./build-rpm.sh -v 1.0.0 -a amd64
```

This creates: `dist/SafeChainAgent-1.0.0-amd64.rpm`

### Options

- `-v VERSION` - Version number (required, e.g., `1.0.0` or `dev`)
- `-a ARCH` - Architecture (required, `arm64` or `amd64`)
- `-b BIN_DIR` - Binary directory (optional, default: `./bin`)
- `-o OUTPUT_DIR` - Output directory (optional, default: `./dist`)
- `-h` - Show help

### Examples

```bash
# Build for x86_64
./build-rpm.sh -v 1.0.0 -a amd64

# Build for ARM64
./build-rpm.sh -v 1.0.0 -a arm64

# Build with custom binary directory
./build-rpm.sh -v 1.0.0 -a amd64 -b /path/to/binaries

# Build development version
./build-rpm.sh -v dev -a amd64
```

## Package Details

### systemd Service Configuration

The package installs a systemd service that:
- Runs as root
- Starts automatically at boot (`WantedBy=multi-user.target`)
- Restarts automatically on failure (`Restart=always`)
- Logs to `/var/log/aikidosecurity/safechainagent/`

### Installation Process

1. **Pre-install**: Stops existing service if running
2. **Install**: Copies binaries and systemd unit file
3. **Post-install**: 
   - Reloads systemd daemon
   - Enables the service
   - Starts the service

### Uninstallation

```bash
sudo rpm -e safechain-agent
```

The uninstall process will:
1. Stop the service
2. Disable the service
3. Remove all installed files
4. Clean up log and runtime directories

## Managing the Service

```bash
# Check status
sudo systemctl status safechain-agent

# Stop the service
sudo systemctl stop safechain-agent

# Start the service
sudo systemctl start safechain-agent

# Restart the service
sudo systemctl restart safechain-agent

# View logs
sudo journalctl -u safechain-agent -f
# or
tail -f /var/log/aikidosecurity/safechainagent/safechain-agent.log
```

## Troubleshooting

### Package won't install
- Check that you have root privileges
- Verify architecture matches your system: `uname -m`
- Check RPM database: `rpm -qa | grep safechain`

### Service won't start
- Check service status: `sudo systemctl status safechain-agent`
- Check logs: `sudo journalctl -u safechain-agent -n 50`
- Verify binary permissions: `ls -la /opt/aikidosecurity/safechainagent/bin/`

### Binaries not found
- Ensure binaries are named correctly: `safechain-agent-linux-{arch}` and `safechain-proxy-linux-{arch}`
- Check that binaries are executable: `chmod +x bin/*`
