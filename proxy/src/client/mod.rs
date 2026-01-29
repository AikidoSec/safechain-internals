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

#[cfg(not(test))]
use ::{
    rama::{
        Service,
        error::{ErrorContext as _, OpaqueError},
        http::{Request, Response, Version, client::EasyHttpWebClient},
        net::client::pool::http::HttpPooledConnectorConfig,
        rt::Executor,
    },
    std::time::Duration,
};

#[cfg(test)]
mod mock_client;

#[cfg(test)]
pub use self::mock_client::new_mock_client as new_web_client;

pub mod transport;

/// Create a new web client that can be cloned and shared.
#[cfg(not(test))]
pub fn new_web_client(
    exec: Executor,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, OpaqueError> {
    let max_active = crate::utils::env::compute_concurrent_request_count();
    let max_total = max_active * 2;

    let tcp_connector = self::transport::new_tcp_connector(exec.clone());
    let tls_config = self::transport::new_tls_connector_config()?;

    Ok(EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(tcp_connector)
        .without_tls_proxy_support()
        .with_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_rustls_and_default_http_version(Some(tls_config), Version::HTTP_11)
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
