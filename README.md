# SafeChain Agent

A lightweight background agent that provides real-time security scanning for your development environment. The SafeChain Agent runs as a daemon, integrates and manages the security tooling seamlessly into your workflow.

## Installation

### macOS (Homebrew)

```bash
brew tap AikidoSec/safechain-agent
brew install safechain-agent
sudo brew services start safechain-agent
```

### Windows

Start PowerShell as Administrator and run:
```powershell
Invoke-WebRequest -Uri "https://github.com/AikidoSec/safechain-agent/releases/latest/download/SafeChainAgent-windows-amd64.msi" -OutFile "SafeChainAgent.msi"
msiexec /i SafeChainAgent.msi /qn /norestart
```

## Uninstall

### macOS (Homebrew)

```bash
sudo brew services stop safechain-agent
brew services stop safechain-agent
brew uninstall safechain-agent
```

### Windows

Start PowerShell as Administrator and run:
```powershell
msiexec /x SafeChainAgent.msi /qn /norestart
```

## Proxy

A security-focused SOCKS5/HTTP(S) system proxy
built with <https://ramaproxy.org/>.

Read more in the proxy readme:
[./docs/proxy.md](./docs/proxy.md).

## Contributing

See our [Contribution docs](.github/CONTRIBUTING.md).
