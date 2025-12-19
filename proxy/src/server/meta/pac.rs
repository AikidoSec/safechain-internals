use std::fmt::Write as _;

use rama::net::address::SocketAddress;

pub(super) fn generate_pac_script(proxy_addr: SocketAddress) -> String {
    let mut domains: Vec<String> = ["TODO"].iter().map(|d| d.to_string()).collect();
    domains.sort_unstable_by_key(|b| std::cmp::Reverse(b.len()));

    let mut out = String::with_capacity(1024 + domains.iter().map(|d| d.len() + 6).sum::<usize>());

    out.push_str(
        r#"function FindProxyForURL(url, host) {
  if (!host) return "DIRECT";
  host = host.toLowerCase();
  var n = host.length;
  // Strip a trailing dot from the hostname (some browsers pass FQDNs like "example.com.")
  if (n && host.charCodeAt(n - 1) === 46) host = host.slice(0, n - 1);
  var proxyAddr = ""#,
    );
    let _ = write!(&mut out, "{proxy_addr}");
    out.push_str(
        r#"; DIRECT";
  var ds = ["#,
    );

    for (i, d) in domains.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(d);
        out.push('"');
    }

    out.push_str(
        r#"];
  for (var i = 0; i < ds.length; i++) {
    var d = ds[i];
    if (host === d) return proxyAddr;
    var dl = d.length;
    if (host.length > dl && host.endsWith("." + d)) return proxyAddr;
  }
  return "DIRECT";
}"#,
    );

    out
}
