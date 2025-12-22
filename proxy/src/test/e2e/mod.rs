mod client;
mod har;
mod runtime;

mod test_connectivity;
mod test_meta;
mod test_proxy;

use rama::telemetry::tracing;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_all() {
    // simple test to ensure that creating and getting runtime works,
    // outside out of any other things that might otherwise go wrong

    let runtime = self::runtime::get().await;

    assert!(runtime.meta_addr().ip_addr.is_loopback());
    assert!(runtime.proxy_addr().ip_addr.is_loopback());
    assert_ne!(runtime.meta_addr(), runtime.proxy_addr());

    tokio::join!(
        self::test_connectivity::test_connectivity(&runtime),
        self::test_meta::test_endpoint(&runtime),
        self::test_proxy::test_proxy(&runtime),
    );
}
