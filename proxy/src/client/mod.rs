//! centralized (web) client creation
//!
//! This is important as it allows us for e2e tests,
//! to easily swap out the real client/connector stack
//! with a mock server that can emulate all egress traffic.
//!
//! Make sure to always use this module instead,
//! expanding it with opt-in customization if required,
//! instead of rama/thirdparty clients as to ensure
//! e2e test suites do not make actual external network requests.

#[cfg(all(not(test), feature = "bench"))]
use ::{
    parking_lot::Mutex,
    rama::{combinators::Either, net::address::SocketAddress},
    std::sync::LazyLock,
};
#[cfg(not(test))]
use ::{
    rama::{
        Service,
        error::{ErrorContext as _, OpaqueError},
        http::{Request, Response, Version, client::EasyHttpWebClient},
        net::client::pool::http::HttpPooledConnectorConfig,
        rt::Executor,
        tcp::client::service::TcpConnector,
    },
    std::time::Duration,
};

#[cfg(test)]
mod mock_client;

#[cfg(test)]
pub use self::mock_client::new_mock_client as new_web_client;

#[cfg(all(not(test), feature = "bench"))]
static EGRESS_ADDRESS_OVERWRITE: LazyLock<Mutex<Option<SocketAddress>>> =
    LazyLock::new(Default::default);

#[cfg(all(not(test), feature = "bench"))]
pub fn set_egress_address_overwrite(address: SocketAddress) {
    let mut overwrite = EGRESS_ADDRESS_OVERWRITE.lock();
    *overwrite = Some(address);
}

/// Create a new web client that can be cloned and shared.
#[cfg(not(test))]
pub fn new_web_client(
    exec: Executor,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, OpaqueError> {
    let max_active = crate::utils::env::compute_concurrent_request_count();
    let max_total = max_active * 2;

    let tcp_connector = TcpConnector::new(exec);

    #[cfg(all(not(test), feature = "bench"))]
    let tcp_connector = match *EGRESS_ADDRESS_OVERWRITE.lock() {
        Some(value) => tcp_connector.with_connector(Either::A(value)),
        None => tcp_connector.with_connector(Either::B(())),
    };

    Ok(EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(tcp_connector)
        .without_tls_proxy_support()
        .without_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_boringssl_and_default_http_version(None, Version::HTTP_11)
        .with_default_http_connector(Executor::default())
        .try_with_connection_pool(HttpPooledConnectorConfig {
            max_total,
            max_active,
            wait_for_pool_timeout: Some(Duration::from_secs(120)),
            idle_timeout: Some(Duration::from_secs(300)),
        })
        .context("create connection pool for proxy web client")?
        .build_client())
}
