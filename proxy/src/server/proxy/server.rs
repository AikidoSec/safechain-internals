use std::convert::Infallible;

use rama::{
    Layer as _, Service,
    error::{BoxError, OpaqueError},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Body,
        layer::{
            compression::CompressionLayer, map_response_body::MapResponseBodyLayer,
            trace::TraceLayer,
        },
        server::HttpServer,
    },
    layer::ConsumeErrLayer,
    net::{proxy::ProxyTarget, tls::server::TlsPeekRouter},
    rt::Executor,
    stream::Stream,
    tcp::client::service::DefaultForwarder,
    telemetry::tracing::{self, Level},
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(feature = "har")]
use crate::diagnostics::har::HARExportLayer;

#[cfg(feature = "har")]
use rama::{
    http::layer::har::extensions::RequestComment, layer::AddInputExtensionLayer,
    utils::str::arcstr::arcstr,
};

use crate::{firewall::Firewall, server::connectivity::CONNECTIVITY_DOMAIN};

#[derive(Debug, Clone)]
pub(super) struct MitmServer<S> {
    inner: S,
    mitm_all: bool,
    firewall: Firewall,
    forwarder: DefaultForwarder,
}

pub(super) fn new_mitm_server<S: Stream + ExtensionsMut + Unpin>(
    guard: ShutdownGuard,
    mitm_all: bool,
    tls_acceptor: TlsAcceptorLayer,
    firewall: Firewall,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> Result<MitmServer<impl Service<S, Output = (), Error = BoxError> + Clone>, OpaqueError> {
    let https_svc = (
        TraceLayer::new_for_http(),
        ConsumeErrLayer::trace(Level::DEBUG),
        #[cfg(feature = "har")]
        (
            AddInputExtensionLayer::new(RequestComment(arcstr!("http(s) MITM server"))),
            har_export_layer,
        ),
        MapResponseBodyLayer::new(Body::new),
        CompressionLayer::new(),
    )
        .into_layer(super::client::new_https_client(firewall.clone())?);

    let http_server = HttpServer::auto(Executor::graceful(guard.clone())).service(https_svc);

    let inner = TlsPeekRouter::new((tls_acceptor).into_layer(http_server.clone()))
        .with_fallback(http_server);

    Ok(MitmServer {
        inner,
        mitm_all,
        firewall,
        forwarder: DefaultForwarder::ctx(Executor::graceful(guard)),
    })
}

impl<T, S> Service<S> for MitmServer<T>
where
    T: Service<S, Output = (), Error = BoxError>,
    S: Unpin + Stream + ExtensionsMut,
{
    type Output = T::Output;
    type Error = Infallible;

    async fn serve(&self, stream: S) -> Result<Self::Output, Self::Error> {
        let maybe_proxy_target = stream.extensions().get().cloned();

        let result = if !self.mitm_all
            && !maybe_proxy_target
                .as_ref()
                .and_then(|ProxyTarget(target)| target.host.as_domain())
                .map(|domain| CONNECTIVITY_DOMAIN.eq(domain) || self.firewall.match_domain(domain))
                .unwrap_or_default()
        {
            tracing::debug!("transport-forward incoming stream: target = {maybe_proxy_target:?}",);
            self.forwarder.serve(stream).await
        } else {
            tracing::debug!(
                "MITM (all? {}) incoming stream: target = {maybe_proxy_target:?}",
                self.mitm_all,
            );
            self.inner.serve(stream).await
        };

        if let Err(err) = result {
            tracing::debug!(
                "mitm server finished with error for target = {maybe_proxy_target:?}: {err}"
            );
        }

        Ok(())
    }
}
