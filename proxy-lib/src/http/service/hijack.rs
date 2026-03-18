use std::convert::Infallible;

use rama::{
    Service,
    http::{
        HeaderValue, Request, Response, StatusCode,
        header::CONTENT_TYPE,
        service::web::{
            Router,
            response::{Html, IntoResponse},
        },
    },
    net::address::Domain,
};

/// The proxy exposes a special “hijack domain” that is intercepted and
/// handled locally by the proxy itself, rather than being resolved externally.
///
/// By default, this domain serves a placeholder page. Once the proxy
/// is active and traffic is correctly routed through it, the hijack domain
/// becomes a useful diagnostic and bootstrap tool.
///
/// The hijack service provides the following resources:
///
/// - `/` (Homepage)
///   A simple HTML page indicating that the hijack domain is being served by the proxy.
///
/// - `/ping`
///   A lightweight connectivity and health check endpoint.
///   Returns `200 OK` when the request is successfully intercepted
///   and handled by the proxy. This can be used both to verify setup
///   and as a heartbeat endpoint for external daemons or monitoring systems.
///
/// - `/data/root.ca.pem`
///   Exposes the public CA certificate used by the proxy.
///   This can be downloaded and installed to trust the proxy for TLS interception.
///
/// ### Purpose
///
/// The hijack domain serves three main purposes:
///
/// 1. Connectivity verification:
///    Confirms that traffic is flowing through the proxy.
///
/// 2. MITM validation:
///    Verifies that the interception pipeline is working end to end.
///
/// 3. Certificate distribution:
///    Provides an easy way to retrieve the proxy’s CA certificate during setup.
///
/// ### Expected Behaviour
///
/// When the hijack domain is working correctly,
/// accessing any of its resources (homepage, `/ping`, or the CA download) guarantees that:
///
/// 1. The L4 proxy is running.
/// 2. Client traffic is routed through the proxy.
/// 3. The BridgeIO / MITM flow is functioning, including:
///    - TCP connectivity
///    - TLS interception (for HTTPS traffic)
///    - HTTP handling
///
/// The `/ping` endpoint can also be used as a periodic health
/// check by external processes. That said, on macOS, the system already manages the
/// lifecycle of the app extension and ensures it remains active.
/// Additionally, the extension status can be inspected via the `status` CLI command
/// in the host application.
///
/// If the hijack domain is not intercepted and instead resolves externally
/// or fails to load, it indicates that the proxy is not active or traffic
/// is not being routed through it.
///
/// ### Typical Usage
///
/// - During development: verify proxy setup using `/ping`
/// - During onboarding: retrieve and install the CA certificate
/// - During monitoring: use `/ping` as a heartbeat endpoint if needed
/// - During debugging: confirm whether traffic is properly intercepted
pub const HIJACK_DOMAIN: Domain = Domain::from_static("mitm.ramaproxy.org");

pub fn new_service(
    root_ca_pem: &'static [u8],
) -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new()
        .with_get("/", Html(STATIC_INDEX_PAGE))
        .with_get("/ping", StatusCode::OK)
        .with_get("/data/root.ca.pem", move || {
            let mut resp = root_ca_pem.into_response();
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            );
            std::future::ready(resp)
        })
}

const STATIC_INDEX_PAGE: &str = include_str!("./hijack_index.html");
