# SafeChain Ultimate

A lightweight background agent that provides real-time security scanning for your development environment. The SafeChain Ultimate runs as a daemon, integrates and manages the security tooling seamlessly into your workflow.

## Install / Upgrade

### macOS

Download and run the latest PKG installer from the [releases page](https://github.com/AikidoSec/safechain-internals/releases).

Or install via command line:
```bash
curl -LO "https://github.com/AikidoSec/safechain-internals/releases/latest/download/SafeChainUltimate.pkg"
echo "YOUR_TOKEN" > /tmp/aikido_endpoint_token.txt && sudo installer -pkg SafeChainUltimate.pkg -target /
```

### Windows

Download and run the latest MSI installer from the [releases page](https://github.com/AikidoSec/safechain-internals/releases).

Or start PowerShell as Administrator and run:
```powershell
Invoke-WebRequest -Uri "https://github.com/AikidoSec/safechain-internals/releases/latest/download/SafeChainUltimate.msi" -OutFile "SafeChainUltimate.msi"
msiexec /i SafeChainUltimate.msi /qn /norestart AIKIDO_TOKEN=YOUR_TOKEN
```

## MDM Installs

### CA Certificates

When deploying via an MDM solution (e.g. Jamf, Mosyle, Kandji), the CA certificate can be pushed by the MDM rather than installed interactively by the agent.

Create the flag file before running the `.pkg` installer:

```bash
touch /tmp/aikido_endpoint_mdm_ca_install.txt
```

When this flag is present, after the `.pkg` install completes the daemon will:
1. Start the proxy.
2. Download the CA certificate to the run directory (path below) — this is the file your MDM configuration profile should deploy as a trusted root CA.
3. Poll every minute for up to 20 minutes until the MDM has installed the certificate into the system trust store.
4. Only once the certificate is trusted: apply system proxy settings and begin sending heartbeats.

**CA certificate path (reference this in your MDM configuration profile):**

- **macOS:** `/Library/Application Support/AikidoSecurity/SafeChainUltimate/run/safechain-proxy-ca-crt.pem`
- **Windows:** `%ProgramData%\AikidoSecurity\SafeChainUltimate\run\safechain-proxy-ca-crt.pem`

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
