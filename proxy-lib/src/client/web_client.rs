use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    http::{Request, Response, Version, client::EasyHttpWebClient},
    rt::Executor,
    tls::rustls::dep::rustls::ClientConfig,
};
use rustls_platform_verifier::ConfigVerifierExt;

// Create a new web client that can be cloned and shared.
pub fn new_web_client()
-> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    let mut config = ClientConfig::with_platform_verifier().context("create platform verifier")?;

    // NOTE replace with rama-built-in platform verifier
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        // fallback to HTTP/1.1 as default HTTP version in case
        // no protocol negotation happens on layers such as TLS (e.g. ALPN)
        .with_tls_support_using_rustls_and_default_http_version(
            Some(config.into()),
            Version::HTTP_11,
        )
        .with_default_http_connector(Executor::default())
        .try_with_default_connection_pool()
        .context("create connection pool for proxy web client")?
        .build_client())
}
