use std::fmt::Write as _;

use rama::{
    bytes::Bytes,
    net::address::{Domain, SocketAddress},
    utils::str::smol_str::ToSmolStr,
};

use crate::http::service::connectivity::CONNECTIVITY_DOMAIN;

#[derive(Debug)]
pub struct PacScriptGenerator {
    buffer: String,
    domains: Vec<String>,
}

// NOTE: for now this has hardcoded
// a fail-open policy such that if the proxy fails
// it will return a DIRECT instruction,
// to let the traffic go through anyway.
//
// You can make it configurable in future if you wish,
// or hardcode it to not do that, by (optionally)
// removing the ;DIRECT part after the proxy addr.

impl PacScriptGenerator {
    pub(super) fn new(proxy_addr: SocketAddress) -> Self {
        let mut out = String::new();

        // NOTE if you ever need to make use of windows-only IPv6 utilities
        // (for now we do not use any utilities) in your Pac SCRIPT (for WINDOWS only)
        // you need to define and serve fro ma function FindProxyForURLEx instead...
        //
        // Cfr: <https://learn.microsoft.com/en-us/windows/win32/winhttp/ipv6-aware-proxy-helper-api-definitions>

        out.push_str(
            r#"function FindProxyForURL(url, host) {
    if (!host) { return "DIRECT"; }
    host = host.toLowerCase();
    var n = host.length;
    // Strip a trailing dot from the hostname (some browsers pass FQDNs like "example.com.")
    if (n && host.charCodeAt(n - 1) === 46) { host = host.slice(0, n - 1); }
    var proxyAddr = "PROXY "#,
        );
        let _ = write!(&mut out, "{proxy_addr}");
        out.push_str(
            r#"; DIRECT";
    var ds = [""#,
        );
        out.push_str(CONNECTIVITY_DOMAIN.as_str());
        out.push('"');

        Self {
            buffer: out,
            domains: Vec::new(),
        }
    }

    pub fn write_domain(&mut self, domain: &Domain) {
        self.domains.push(domain.to_smolstr().trim().to_lowercase())
    }

    pub(super) fn into_script(mut self) -> Bytes {
        self.domains
            .sort_unstable_by_key(|b| std::cmp::Reverse(b.len()));

        for d in self.domains.iter() {
            self.buffer.push_str(r##",""##);
            self.buffer.push_str(d);
            self.buffer.push('"');
        }

        self.buffer.push_str(
            r#"];
    for (var i = 0; i < ds.length; i++) {
        var d = ds[i];
        if (host === d) { return proxyAddr; }
        var dl = d.length;
        if (host.length > dl && host.endsWith("." + d)) { return proxyAddr; }
    }
    return "DIRECT";
}"#,
        );

        self.buffer.into()
    }
}

#[cfg(test)]
mod tests {
    use rama::crypto::dep::x509_parser::nom::AsBytes;

    use super::*;

    #[test]
    // NOTE: this does not test if the Js script is valid,
    // if you ever get paranoid and want to test that we can do that easily,
    // but it will require us to use rama-js to load the script with a fake PAC runtime,
    // so we can test it e2e :) including if you get even the correct proxy response back from the pac script,
    // given the provided url/host.
    //
    // There are also plenty of PAC validators (offline and online),
    // in case you wanna keep it simple (ad developer-manual) for now,
    // e.g.: <https://thorsenlabs.com/pac>
    fn test_pac_script_generator_basic() {
        let mut generator = PacScriptGenerator::new(SocketAddress::local_ipv4(8080));

        generator.write_domain(&Domain::from_static("example.com"));
        generator.write_domain(&Domain::from_static("aikido.gent"));

        let payload = generator.into_script();
        let payload_str = std::str::from_utf8(payload.as_bytes()).unwrap();

        assert!(
            payload_str.contains("PROXY 127.0.0.1:8080; DIRECT"),
            "payload: {payload_str}"
        );
        assert!(
            payload_str.contains("example.com"),
            "payload: {payload_str}"
        );
        assert!(
            payload_str.contains("aikido.gent"),
            "payload: {payload_str}"
        );
    }
}
