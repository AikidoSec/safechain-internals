mod connector;
pub use self::connector::{
    new_tcp_connector_service_for_internal, new_tcp_connector_service_for_proxy,
};

/// Returns `true` for ports where TLS traffic is commonly expected (443, 8443).
///
/// Used to select a longer peek window for `PeekTlsClientHelloService` only
/// on ports where a TLS ClientHello is actually likely to arrive.
#[inline]
#[must_use]
pub fn is_known_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

/// Returns `true` for ports where HTTP or HTTPS traffic is commonly expected
/// (80, 443, 8080, 8443).
///
/// Used to select a longer peek window for `HttpPeekRouter` on ports where
/// an HTTP request is likely to arrive.
#[inline]
#[must_use]
pub fn is_known_http_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}
