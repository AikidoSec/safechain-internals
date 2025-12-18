# Safe-chain Proxy

A security-focused SOCKS5/HTTP(S) system proxy
built with <https://ramaproxy.org/>.

> Edge Rama Rust docs:
> <https://ramaproxy.org/docs/rama/>

## Quick Start

### Running the Proxy

Run the executable:

```bash
# macOS/Linux
./safechain-proxy

# Windows
safechain-proxy.exe
```

The proxy will automatically find an available port and display it:

```
SafeChain proxy running on 127.0.0.1:54321
```

### Custom interface

By default the safechain-proxy will run on the local Ipv4 interface (127.0.0.1),
on an available port. You can specify a specific (network) "interface" to bind to:

Use the `--bind` or `-b` flag:

```bash
# Long form
./safechain-proxy --bind 127.0.0.1:3128

# Short form
./safechain-proxy -b '[::]:3128'
```

### Usage Command

```bash
./safechain-proxy --help
```

## Using the Proxy

Configure your package manager or HTTP client to route traffic through the proxy.

### npm / Node.js

```bash
npm config set proxy http://127.0.0.1:3128
npm config set https-proxy http://127.0.0.1:3128

# Now npm install will route through the proxy
npm install
```

To revert:
```bash
npm config delete proxy
npm config delete https-proxy
```

### Yarn

```bash
yarn config set httpProxy http://127.0.0.1:3128
yarn config set httpsProxy http://127.0.0.1:3128
```

### pnpm

```bash
pnpm config set proxy http://127.0.0.1:3128
pnpm config set https-proxy http://127.0.0.1:3128
```

### Bun

```bash
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
bun install
```

### curl

```bash
curl -x http://127.0.0.1:3128 https://example.com
```

### Environment Variables (any tool)

Set these environment variables to make any HTTP client use the proxy:

```bash
# macOS/Linux
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128

# Windows (Command Prompt)
set http_proxy=http://127.0.0.1:3128
set https_proxy=http://127.0.0.1:3128

# Windows (PowerShell)
$env:http_proxy = "http://127.0.0.1:3128"
$env:https_proxy = "http://127.0.0.1:3128"
```

## Troubleshooting

### Port Already in Use

If you get a "port already in use" error:
1. Try running without `--port` to let the OS assign an available port
2. Or choose a different port: `./safechain-proxy --port 8080`

### Proxy Not Working

1. Verify the proxy is running and note the port from the console output
2. Check your client is configured with the correct port
3. Ensure firewall settings allow connections to the proxy

### Verbose Logging

Enable debug logging to troubleshoot issues:

```bash
# macOS/Linux
RUST_LOG=debug ./safechain-proxy

# Windows (Command Prompt)
set RUST_LOG=debug
safechain-proxy.exe

# Windows (PowerShell)
$env:RUST_LOG = "debug"
.\safechain-proxy.exe
```

## Stopping the Proxy

Press `Ctrl+C` to stop the proxy. It will gracefully shut down, waiting up to 30 seconds for active connections to complete.

## What Does It Do?

The Safe-chain proxy intercepts HTTP/HTTPS traffic from package managers and other tools, allowing Safe-chain to:
- Scan packages for malware before installation
- Monitor registry requests
- Block malicious packages
- Provide visibility into dependency downloads

## Security

- The proxy only listens on `127.0.0.1` (localhost) - it cannot be accessed from other machines
- All HTTPS traffic is tunneled securely using CONNECT
- Body size limits prevent memory exhaustion attacks
