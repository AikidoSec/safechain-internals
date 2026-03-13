# Proxy Auto-Configuration (PAC)

> A proxy auto-config (PAC) file defines how web browsers and other user agents can automatically choose the appropriate proxy server (access method) for fetching a given URL. A PAC file contains a JavaScript function `FindProxyForURL(url, host)`.
> — [Wikipedia](https://en.wikipedia.org/wiki/Proxy_auto-config)

Proxies act as intermediaries, sitting between a client and a destination (egress) server. In this architecture, a proxy functions simultaneously as a **server** (to the client) and a **client** (to the destination).

## How Clients Connect to Proxies

Network clients generally use one of three primary protocols to communicate with a proxy:

* **HTTP CONNECT**: Used primarily for tunneling encrypted HTTPS traffic. [Learn more on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/CONNECT).
* **HTTP Proxy**: Sending cleartext requests with a fully qualified URI to the proxy server.
* **SOCKS5**: A transport-layer protocol that performs a handshake before data transmission. [Learn more on Wikipedia](https://en.wikipedia.org/wiki/SOCKS).

### Proxy Discovery Methods

Clients typically "find" a proxy through three methods:

1. **Hardcoded**: The application logic is locked to a specific address.
2. **Manual Configuration**: The user explicitly enters a proxy URL (e.g., `http://127.0.0.1:1234`) in the app settings or as an argument, flag or environment variable when starting the application.
3. **PAC (Proxy Auto-Configuration)**: The system is pointed to a URL where it downloads a script to determine routing logic dynamically. **This document focuses on the PAC approach.**

## How PAC Works

A PAC file is a JavaScript file evaluated by the client's networking stack. It must implement the `FindProxyForURL` function.

### The `FindProxyForURL(url, host)` Function

The client passes two arguments to this function:

* **url**: The full destination URL (e.g., `https://example.com:8443/foo/bar?baz=1`).
* **host**: The host component extracted from the URL (e.g., `example.com`).

### Return Directives

The function returns a string instructing the client on how to proceed:

* **`DIRECT`**: Connect to the destination server directly, bypassing the proxy.
* **`PROXY host:port`**: Connect via the specified HTTP proxy.

> [!NOTE]
> While some clients support `SOCKS`, `HTTPS`, or `SOCKS5` directives, `PROXY` and `DIRECT` are the most universally compatible across all platforms and browsers.
>
> Unless you really need to and know for sure it is supported it is best to only use
> the `PROXY` and `DIRECT` directives.

### Fallback Logic

You can return multiple options separated by a semicolon (`;`). The client will attempt them in order:

```javascript
function FindProxyForURL(url, host) {
  // Try the proxy first; if the proxy is unreachable, connect directly.
  return 'PROXY proxy.example.com:8080; DIRECT';
}

```

If you omit `; DIRECT`, and the proxy server is offline, the client will fail to connect to the target website entirely, even if the target website itself is healthy.

## Why Use PAC?

PAC offers several advantages over static proxy configurations:

* **Dynamic Intelligence**: Since the file is served over HTTP, you can generate it dynamically based on the requester's IP, `User-Agent`, or current network state.
* **Reduced Load**: You can instruct the client to only use the proxy for specific domains, allowing "uninteresting" traffic to stay on the local network/direct internet.
* **Universal Support**: Despite being an older technology, it is supported by virtually every modern OS (Windows, macOS, Linux, iOS, Android) and application.

## Implementation in Safechain Proxy

The `safechain` proxy provides a built-in meta-server to host and generate these files.

* **Logic Location**: `proxy/src/firewall/pac.rs` (Handles the generation of domain lists).
* **Router Location**: `proxy/src/server/meta/mod.rs` (Serves the file).

The meta-server serves the generated script at the **`/pac`** endpoint.

## Further Resources

* **[MDN: Proxy Auto-Configuration](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file)**: Excellent documentation on built-in helper functions (like `shExpMatch`). *Note: These functions can be slow; Safechain often uses optimized custom logic instead.*
* **[Cloudflare: PAC Best Practices](https://developers.cloudflare.com/cloudflare-one/networks/resolvers-and-proxies/proxy-endpoints/best-practices/)**: Modern performance tips.
* **[Microsoft: WinHTTP IPv6 Extensions](https://learn.microsoft.com/en-us/windows/win32/winhttp/ipv6-aware-proxy-helper-api-definitions)**: Information on `FindProxyForURLEx`, used specifically by Win32 applications for IPv6 support (useful only if you need to take advantage of builtin Ipv6 utilities and only supported for windows applications running the Win32 stack).
