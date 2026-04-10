# L4 Proxy

Other L4 Proxy docs:

- [./l4_proxy/apple.md](./l4_proxy/apple.md): macOS transparent proxy packaging,
  CLI usage, and developer build instructions.
- [./l4_proxy/windows-driver.md](./l4_proxy/windows-driver.md):
  windows (kernel) driver docs specifically for the Windows L4 proxy.

## Intro

A L4 proxy, or within context of safechain also called "transparent proxy",
is a proxy which lives on Layer 4 (L4) of the OSI (conceptual model). Which basically
means it sits in the middle of UDP/TCP sockets instead of relying on higher level
application protocols (Layer 7, L7) such as HTTP Proxy CONNECT or SOCKS5(H).

The reason this type of L4 proxy is labeled a "transparent" proxy,
is because the client is not aware that it is even going via a proxy,
the flow is however pretty much the same:

```plain
App -> Proxy -> Server
```

Benefits of an L4 Proxy are:

- the client does not need to cooperate,
  and cannot even prevent going via the (L4) proxy
- even if the client goes via a proxy explicitly (configured via system or for that app specifically)
  the traffic will still go via the (L4) proxy

In the latter case the flow is:

```plain
App -> L4-Proxy -> Proxy -> Server
```

Or in case there is _also_ a VPN configured,
, the L7 proxy is compatible with the VPN _and_
the destination is a public address:

```plain
App -> L4-Proxy -> VPN -> Proxy -> Server
```

The biggest disatvantage of L4 (Transparent) proxies is that
they are a lot harder to develop and manage. And in case they are
going "wrong" in production they can do a lot more damage. That said,
damage-wise "system" configured proxies can cause a similar kind of "damage",
such as causing network connections to fail fully or partly.

To prevent such damage as much as possible it is recommended that:

- L4 proxies have where possible a "fail-open" policy
- (Semi) automated ways for users to report diagnostics to a C&C,
  to aid in troubleshooting

A fail-open policy is however not always "fully" possible,
so great care must be taken as developers or such proxies.

## Ingress Traffic

Given the client (app) is _not_ aware it is going via the (L4) Proxy,
how does the (ingress) traffic end up passing through the (L4) Proxy?

Well that depends on the platform:

- For MacOS this is by making use of the apple "Network Extension" (NE)
  framework, where the proxy is still ran in user-space but very low
  on the stack within a secure environment with elevated rights. It is in
  that position that it can receive all or some of the TCP/UDP traffic.

  See [./l4_proxy/apple.md](./l4_proxy/apple.md) for more information.

- For Linux it is by using dedicated nftables with a dedicated policy routing rules.
  No documentation can be found yet in this repository as Linux is not yet an platform
  officially supported by safechain-internals proxies. However you can find some docs
  and playground example for this platform and approach at:
  <https://github.com/plabayo/rama/blob/main/examples/linux_tproxy_tcp.rs>

- For Windows this is done using the
  [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page),
  for which you need to write and manage a dedicated Windows Kernel Driver.

  See [./l4_proxy/windows-driver.md](./l4_proxy/windows-driver.md) for more information.

To recap, regardless of the platform, the L4 (MITM transparent) proxy runs as a process in user space,
or depending on the platform as 2 proxies (1 for IPv4 and 1 for IPv6), but how the traffic "ends up"
in the proxy (to "pass through") is platform specific.