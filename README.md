# SafeChain Ultimate

A lightweight background agent that provides real-time security scanning for your development environment. The SafeChain Ultimate runs as a daemon, integrates and manages the security tooling seamlessly into your workflow.

## Installation

### macOS (Homebrew)

```bash
brew tap AikidoSec/safechain-ultimate
brew install safechain-ultimate
sudo brew services start safechain-ultimate
```

### Windows

Start PowerShell as Administrator and run:
```powershell
Invoke-WebRequest -Uri "https://github.com/AikidoSec/safechain-ultimate/releases/latest/download/SafeChainUltimate-windows-amd64.msi" -OutFile "SafeChainUltimate.msi"
msiexec /i SafeChainUltimate.msi /qn /norestart
```

## Uninstall

### macOS (Homebrew)

```bash
sudo brew services stop safechain-ultimate
brew uninstall safechain-ultimate
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
