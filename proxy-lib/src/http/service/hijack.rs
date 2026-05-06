use std::convert::Infallible;

use rama::{
    Service,
    bytes::Bytes,
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

use crate::http::firewall::Firewall;

/// The proxy exposes a special “hijack domain” that is intercepted and
/// handled locally by the proxy itself, rather than being resolved externally.
/// The hijack service provides the following resources:
/// - `/`: simple html page, showing that it's being served by proxy and not externally.
/// - `/ping`: health check, can be used to verify setup
/// - `/data/root.ca.pem`: Exposes the public CA certificate used by the proxy.
///
/// ### Expected Behaviour
///
/// When the hijack domain is working correctly,
/// accessing any of its resources (homepage, `/ping`, or the CA download) guarantees that:
/// 1. The L4 proxy is running.
/// 2. Client traffic is routed through the proxy.
/// 3. The BridgeIO / MITM flow is functioning, including:
///    - TCP connectivity
///    - TLS interception (for HTTPS traffic)
///    - HTTP handling
///
/// If the hijack domain is not intercepted and instead resolves externally
/// or fails to load, it indicates that the proxy is not active or traffic
/// is not being routed through it.
pub const HIJACK_DOMAIN: Domain = Domain::from_static("mitm.ramaproxy.org");

pub fn new_service(
    root_ca_pem: Bytes,
    firewall: Firewall,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new()
        .with_get("/", Html(STATIC_INDEX_PAGE))
        .with_get("/ping", StatusCode::OK)
        .with_get("/data/root.ca.pem", move || {
            let mut resp = root_ca_pem.clone().into_response();
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            );
            std::future::ready(resp)
        })
        .with_post("/config/refresh", move |req: Request| {
            if !firewall.is_agent_authorized(&req) {
                return std::future::ready(StatusCode::UNAUTHORIZED.into_response());
            }
            firewall.trigger_refresh_all();
            std::future::ready(StatusCode::NO_CONTENT.into_response())
        })
}

const STATIC_INDEX_PAGE: &str = include_str!("./hijack_index.html");
