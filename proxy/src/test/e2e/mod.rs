#![allow(unused)]

mod client;
mod runtime;

mod test_connectivity;
mod test_meta;
mod test_proxy_firewall_vscode;
mod test_proxy_no_firewall;

use rama::telemetry::tracing;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_runtime_get() {
    // simple test to ensure that creating and getting runtime works,
    // outside out of any other things that might otherwise go wrong

    let runtime = self::runtime::get().await;
    assert!(runtime.meta_addr().ip_addr.is_loopback());
    assert!(runtime.proxy_addr().ip_addr.is_loopback());
    assert_ne!(runtime.meta_addr(), runtime.proxy_addr());
}
