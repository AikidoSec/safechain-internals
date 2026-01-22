# SafeChain Ultimate

A lightweight background agent that provides real-time security scanning for your development environment. The SafeChain Ultimate runs as a daemon, integrates and manages the security tooling seamlessly into your workflow.

## Installation

### macOS

Download and run the latest PKG installer from the [releases page](https://github.com/AikidoSec/safechain-internals/releases).

Or install via command line:
```bash
curl -LO "https://github.com/AikidoSec/safechain-internals/releases/latest/download/SafeChainUltimate-macos-arm64.pkg"
sudo installer -pkg SafeChainUltimate-macos-arm64.pkg -target /
```

### Windows

Start PowerShell as Administrator and run:
```powershell
Invoke-WebRequest -Uri "https://github.com/AikidoSec/safechain-internals/releases/latest/download/SafeChainUltimate-windows-amd64.msi" -OutFile "SafeChainUltimate.msi"
msiexec /i SafeChainUltimate.msi /qn /norestart
```

## Uninstall

### macOS

Run the uninstall script that was installed with the package:
```bash
sudo "/Library/Application Support/AikidoSecurity/SafeChainUltimate/scripts/uninstall"
```

### Windows

Start PowerShell as Administrator and run:
```powershell
msiexec /x SafeChainUltimate.msi /qn /norestart
```

## Proxy

A security-focused SOCKS5/HTTP(S) system proxy
built with <https://ramaproxy.org/>.

Read more in the proxy readme:
[./docs/proxy.md](./docs/proxy.md).

## Contributing

See our [Contribution docs](.github/CONTRIBUTING.md).
