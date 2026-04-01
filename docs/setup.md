## Install / Upgrade

### macOS

Download and run the latest PKG installer from the [releases page](https://github.com/AikidoSec/safechain-internals/releases).

Or install via command line:
```bash
curl -LO "https://github.com/AikidoSec/safechain-internals/releases/latest/download/EndpointProtection.pkg"
echo "YOUR_TOKEN" > /tmp/aikido_endpoint_token.txt && sudo installer -pkg EndpointProtection.pkg -target /
```

### Windows

Download and run the latest MSI installer from the [releases page](https://github.com/AikidoSec/safechain-internals/releases).

Or start PowerShell as Administrator and run:
```powershell
Invoke-WebRequest -Uri "https://github.com/AikidoSec/safechain-internals/releases/latest/download/EndpointProtection.msi" -OutFile "EndpointProtection.msi"
msiexec /i EndpointProtection.msi /qn /norestart AIKIDO_TOKEN=YOUR_TOKEN
```

## Uninstall

### macOS

Run the uninstall script that was installed with the package:
```bash
sudo "/Library/Application Support/AikidoSecurity/EndpointProtection/scripts/uninstall"
```

### Windows

Start PowerShell as Administrator and run:
```powershell
msiexec /x EndpointProtection.msi /qn /norestart
```

## Proxy

A security-focused SOCKS5/HTTP(S) system proxy built with <https://ramaproxy.org/>.
Read more in the proxy readme: [./docs/proxy.md](./docs/proxy.md).

## CA Certificates

Aikido Endpoint installs a proxy CA certificate into the OS trust store and configures trust for tools that maintain their own certificate stores (Node.js, pip, Firefox, Docker). JetBrains IDEs use the OS trust store automatically but require a restart.

See [CA Certificates](./docs/ca-certs.md) for details on each supported tool.

## Contributing

See our [Contribution docs](.github/CONTRIBUTING.md).
