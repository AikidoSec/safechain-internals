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
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    http::{Request, Response, Version, client::EasyHttpWebClient},
};

#[cfg(test)]
mod mock_client;

#[cfg(test)]
pub use self::mock_client::new_mock_client as new_web_client;

/// Create a new web client that can be cloned and shared.
#[cfg(not(test))]
pub fn new_web_client()
-> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, OpaqueError> {
    Ok(EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_boringssl_and_default_http_version(None, Version::HTTP_11)
        .with_default_http_connector()
        .try_with_default_connection_pool()
        .context("create connection pool for proxy web client")?
        .build_client())
}
