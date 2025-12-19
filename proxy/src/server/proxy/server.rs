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
    net::{address::DomainTrie, proxy::ProxyTarget},
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

use crate::firewall::{BLOCK_DOMAINS_CHROME, BLOCK_DOMAINS_VSCODE};

#[derive(Debug, Clone)]
pub(super) struct MitmServer<S> {
    inner: S,
    mitm_all: bool,
    forwarder: DefaultForwarder,
    target_domains: DomainTrie<()>,
}

pub(super) fn new_mitm_server<S: Stream + ExtensionsMut + Unpin>(
    guard: ShutdownGuard,
    mitm_all: bool,
    tls_acceptor: TlsAcceptorLayer,
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
        .into_layer(super::client::new_https_client()?);

    let inner =
        tls_acceptor.into_layer(HttpServer::auto(Executor::graceful(guard)).service(https_svc));

    // TODO: this should be managed to allow updates and other
    // dynamic featurues (in future)
    // TODO^2: this is similar logic from client, we need to merge and centralize this logic
    let mut target_domains = DomainTrie::new();
    for domain in BLOCK_DOMAINS_VSCODE {
        target_domains.insert_domain(domain, ());
    }
    for domain in BLOCK_DOMAINS_CHROME {
        target_domains.insert_domain(domain, ());
    }

    Ok(MitmServer {
        inner,
        mitm_all,
        forwarder: DefaultForwarder::ctx(),
        target_domains,
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
                .map(|domain| self.target_domains.is_match_parent(domain))
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
