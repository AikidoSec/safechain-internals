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

#[cfg(test)]
use rama::{
    Service,
    error::{BoxError, extra::OpaqueError},
    http::{Request, Response},
    rt::Executor,
};

#[cfg(test)]
mod mock_server;

#[cfg(test)]
#[inline(always)]
pub fn new_http_client_for_proxy(
    exec: Executor,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    #[cfg(test)]
    let connector = self::mock_server::new_mock_tcp_connector(exec.clone());
    safechain_proxy_lib::http::client::new_http_client_for_proxy_with_connector(exec, connector)
}

#[cfg(test)]
pub use self::{
    mock_server::new_mock_tcp_connector as new_tcp_connector_service_for_internal,
    mock_server::new_mock_tcp_connector as new_tcp_connector_service_for_proxy,
    new_http_client_for_proxy as new_http_client_for_internal,
};

#[cfg(not(test))]
pub use safechain_proxy_lib::{
    http::client::{new_http_client_for_internal, new_http_client_for_proxy},
    tcp::{new_tcp_connector_service_for_internal, new_tcp_connector_service_for_proxy},
};
