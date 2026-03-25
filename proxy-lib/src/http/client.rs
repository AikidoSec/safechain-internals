use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    http::{Request, Response, Version, client::EasyHttpWebClient},
    io::Io,
    net::{client::ConnectorService, tls::client::ServerVerifyMode},
    rt::Executor,
    tls::{boring::client::TlsConnectorDataBuilder, rustls::dep::rustls::ClientConfig},
};
use rustls_platform_verifier::ConfigVerifierExt;

#[inline(always)]
// create a new http client for proxy purposes with default proxy (tcp) connector.
pub fn new_http_client_for_proxy(
    exec: Executor,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    let connector = crate::tcp::new_tcp_connector_service_for_proxy(exec.clone());
    new_http_client_for_proxy_with_connector(exec, connector)
}

// create a new http client for proxy purposes with the given (tcp) connector.
pub fn new_http_client_for_proxy_with_connector<C>(
    exec: Executor,
    connector: C,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError>
where
    C: ConnectorService<Request, Connection: Io + Unpin> + Clone,
{
    let config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .into_shared_builder();
    Ok(EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(connector)
        .without_tls_proxy_support()
        .with_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_boringssl_and_default_http_version(Some(config), Version::HTTP_11)
        .with_default_http_connector(exec)
        .try_with_default_connection_pool()
        .context("create connection pool for http(s) client for proxy purposes")?
        .build_client())
}

#[inline(always)]
// create a new http client for internal purposes with default internal (tcp) connector.
pub fn new_http_client_for_internal(
    exec: Executor,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    let connector = crate::tcp::new_tcp_connector_service_for_internal(exec.clone());
    new_http_client_for_internal_with_connector(exec, connector)
}

// create a new http client for internal purposes with the given (tcp) connector.
pub fn new_http_client_for_internal_with_connector<C>(
    exec: Executor,
    connector: C,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError>
where
    C: ConnectorService<Request, Connection: Io + Unpin> + Clone,
{
    let mut config = ClientConfig::with_platform_verifier().context("create platform verifier")?;

    // NOTE replace with rama-built-in platform verifier
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(connector)
        .without_tls_proxy_support()
        .with_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_rustls_and_default_http_version(
            Some(config.into()),
            Version::HTTP_11,
        )
        .with_default_http_connector(exec)
        .try_with_default_connection_pool()
        .context("create connection pool for http(s) client for internal purposes")?
        .build_client())
}
