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
        rt::Executor,
        telemetry::tracing,
    },
    std::time::Duration,
};

use {rama::net::client::pool::http::HttpPooledConnectorConfig, std::fmt};

#[cfg(test)]
mod mock_client;

#[cfg(test)]
pub use self::mock_client::new_mock_client as new_web_client;

pub mod transport;

#[derive(Default)]
pub struct WebClientConfig {
    pub pool_cfg: Option<HttpPooledConnectorConfig>,
    #[cfg(all(not(test), feature = "bench"))]
    pub do_not_allow_overwrite: bool,
}

impl fmt::Debug for WebClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebClientConfig").finish()
    }
}

impl WebClientConfig {
    pub fn without_overwrites() -> Self {
        Self {
            pool_cfg: None,
            #[cfg(all(not(test), feature = "bench"))]
            do_not_allow_overwrite: true,
        }
    }

    pub fn with_pool_cfg(mut self, cfg: HttpPooledConnectorConfig) -> Self {
        self.pool_cfg = Some(cfg);
        self
    }
}

/// Create a new web client that can be cloned and shared.
#[cfg(not(test))]
pub fn new_web_client(
    exec: Executor,
    cfg: WebClientConfig,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, OpaqueError> {
    tracing::trace!("new_web_client w/ cfg: {cfg:?}");

    let pool_cfg = cfg.pool_cfg.unwrap_or_else(|| {
        let max_active = crate::utils::env::compute_concurrent_request_count();
        let max_total = max_active * 2;
        HttpPooledConnectorConfig {
            max_total,
            max_active,
            wait_for_pool_timeout: Some(Duration::from_secs(120)),
            idle_timeout: Some(Duration::from_secs(300)),
        }
    });

    let tcp_connector = self::transport::new_tcp_connector(
        exec.clone(),
        self::transport::TcpConnectorConfig {
            #[cfg(all(not(test), feature = "bench"))]
            do_not_allow_overwrite: cfg.do_not_allow_overwrite,
        },
    );
    let tls_config = self::transport::new_tls_connector_config()?;

    Ok(EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(tcp_connector)
        .without_tls_proxy_support()
        .with_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_rustls_and_default_http_version(Some(tls_config), Version::HTTP_11)
        .with_default_http_connector(Executor::default())
        .try_with_connection_pool(pool_cfg)
        .context("create connection pool for proxy web client")?
        .build_client())
}
