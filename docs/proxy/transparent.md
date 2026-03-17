# Transparent Proxy

This document covers the macOS L4 transparent proxy packaging in this repository.
It is the developer-facing wrapper around the Rust transparent proxy extension and
is also the shape intended for future daemon or MDM-driven activation flows.

## macOS Operating Model

The macOS transparent proxy consists of:

- a Rust static library: `proxy-lib-l4-macos`
- a Network Extension app extension embedded in a host app bundle
- a minimal host CLI that manages the `NETransparentProxyManager` profile

The host CLI does not need to remain running after `start`.
Once the profile is installed and the transparent proxy tunnel is started,
macOS manages the extension lifecycle.

The current host CLI exposes three commands:

- `start`
- `stop`
- `status`

`start` can also pass the opaque JSON config consumed by the Rust proxy runtime:

- `--reporting-endpoint URL`
- `--aikido-url URL`
- `--agent-token TOKEN`
- `--agent-device-id DEVICE_ID`
- `--reset-profile`

The `agent token` and `agent device id` map to the Rust-side `agent_identity`
payload expected by `proxy-lib-l4-macos/src/config.rs`.

## Stack Overview

```text
+------------------------------+
| Host CLI                     |
| main.swift                   |
| start / stop / status        |
+--------------+---------------+
               |
               | saves and starts
               v
+------------------------------+
| NETransparentProxyManager    |
| macOS-managed profile        |
+--------------+---------------+
               |
               | launches
               v
+------------------------------+
| Network Extension            |
| Extension/ + Rust staticlib  |
+--------------+---------------+
               |
               | FFI bridge
               v
+------------------------------+
| proxy-lib-l4-macos           |
| transparent proxy runtime    |
+--------------+---------------+
               |
               | provider APIs
               v
+------------------------------+
| rama ffi apple provider      |
| TcpFlow / NE integration     |
+--------------+---------------+
               |
               | proxy engine
               v
+------------------------------+
| rama + safechain_proxy_lib   |
| MITM / firewall / reporting  |
+------------------------------+
```

At a high level: Swift owns profile management, macOS owns extension lifecycle,
the Rust static library hosts the runtime, and Rama provides the Network Extension
FFI/provider surface plus the transparent proxy engine.

Relevant sources:

- Host CLI: [`packaging/macos/xcode/l4-proxy/Host/main.swift`](../../packaging/macos/xcode/l4-proxy/Host/main.swift)
- Xcode packaging: [`packaging/macos/xcode/l4-proxy/Project.yml`](../../packaging/macos/xcode/l4-proxy/Project.yml)
- Rust entrypoint: [`proxy-lib-l4-macos/src/lib.rs`](../../proxy-lib-l4-macos/src/lib.rs)
- Rust TCP proxy service: [`proxy-lib-l4-macos/src/tcp.rs`](../../proxy-lib-l4-macos/src/tcp.rs)
- Rust config schema: [`proxy-lib-l4-macos/src/config.rs`](../../proxy-lib-l4-macos/src/config.rs)
- Rama transparent proxy example: <https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy>
- Rama transparent proxy guide: <https://ramaproxy.org/book/proxies/transparent.html>

## Relevant Files

- Rust transparent proxy library: `proxy-lib-l4-macos/`
- Xcode packaging: `packaging/macos/xcode/l4-proxy/` (Host+Extension)


## Build And Install

The `Justfile` contains the supported developer commands.

Build the Rust static library and generate the Xcode project:

```bash
just macos-l4-build-rust
just macos-l4-xcodegen-generate
```

Build the macOS host app and extension without signing checks:

```bash
just macos-l4-xcodegen-build-debug
```

Build with signing and install the app bundle into `/Applications`:

```bash
just macos-l4-install-signed
```

The install step also registers the embedded extension with `pluginkit`.

## Run As A Developer

Check current state:

```bash
just macos-l4-status
```

Start the transparent proxy with defaults:

```bash
just macos-l4-start
```

Start the transparent proxy with explicit runtime config:

```bash
just macos-l4-start \
  --reporting-endpoint https://example.internal/reporting \
  --aikido-url https://app.aikido.dev \
  --agent-token YOUR_TOKEN \
  --agent-device-id YOUR_DEVICE_ID
```

Stop the transparent proxy:

```bash
just macos-l4-stop
```

Install and immediately start it in one step:

```bash
just run-macos-l4-proxy
```

Reset the saved Network Extension profile before starting:

```bash
just macos-l4-start --reset-profile
```

## Logs

Stream live logs from the host and extension:

```bash
log stream --style compact \
  --predicate 'subsystem == "com.aikido.endpoint.proxy.l4" OR process == "AikidoEndpointL4ProxyExtension" OR process == "AikidoEndpointL4ProxyHost"'
```

Show recent logs from the last 5 minutes:

```bash
log show --last 5m --style compact \
  --predicate 'subsystem == "com.aikido.endpoint.proxy.l4" OR process == "AikidoEndpointL4ProxyExtension" OR process == "AikidoEndpointL4ProxyHost"'
```

Export recent logs to a file for sharing or later analysis:

```bash
mkdir -p .aikido/logs
log show --last 30m --style compact \
  --predicate 'subsystem == "com.aikido.endpoint.proxy.l4" OR process == "AikidoEndpointL4ProxyExtension" OR process == "AikidoEndpointL4ProxyHost"' \
  > .aikido/logs/macos-l4-transparent-proxy.log
```

## Notes For Developers

- The host executable lives inside the installed app bundle at:
  `/Applications/AikidoEndpointL4ProxyHost.app/Contents/MacOS/AikidoEndpointL4ProxyHost`
- `status` reports the current Network Extension state and the saved JSON config, if any.
- The transparent proxy profile is persisted by `NETransparentProxyManager`.
- The extension is expected to be restarted by the system according to the saved profile state;
  the host CLI is a controller, not a long-running supervisor.
- The extension uses the regular keychain backend for the MITM CA because the protected-data
  backend can trigger LocalAuthentication during extension startup.

## Further Reading

Relevant Rama book references:

- Transparent proxy guide: <https://ramaproxy.org/book/proxies/transparent.html>
- Book index: <https://ramaproxy.org/book/>

General Rama documentation:

- <https://ramaproxy.org/docs/rama/>

## Platform Roadmap

### macOS

macOS transparent proxy support is implemented in this repository and is the current reference platform.

### Linux

Transparent proxy support for Linux still needs to be built and delivered in the near future.

### Windows

Transparent proxy support for Windows still needs to be built and delivered in the near future.
