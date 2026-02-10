use std::{fmt, sync::Arc};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    http::client::{ProxyConnector, ProxyConnectorLayer, proxy::layer::HttpProxyConnectorLayer},
    net::{
        address::ProxyAddress,
        client::{ConnectorService, EstablishedClientConnection},
        proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
    },
    proxy::socks5::Socks5ProxyConnectorLayer,
    rt::Executor,
    stream::Stream,
    tcp::client::{Request, service::TcpConnector},
};

enum ForwarderKind {
    Direct(TcpConnector),
    Proxied {
        connector: ProxyConnector<Arc<TcpConnector>>,
        proxy_addr: ProxyAddress,
    },
}

pub(super) struct TcpForwarder {
    kind: ForwarderKind,
}

impl fmt::Debug for TcpForwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpForwarder").finish()
    }
}

impl TcpForwarder {
    pub(super) fn new(exec: Executor, proxy: Option<ProxyAddress>) -> Self {
        let tcp_connector = TcpConnector::new(exec);
        let kind = match proxy {
            Some(proxy_addr) => {
                let connector = ProxyConnectorLayer::required(
                    Socks5ProxyConnectorLayer::required(),
                    HttpProxyConnectorLayer::required(),
                )
                .into_layer(Arc::new(tcp_connector));
                ForwarderKind::Proxied {
                    connector,
                    proxy_addr,
                }
            }
            None => ForwarderKind::Direct(tcp_connector),
        };
        Self { kind }
    }
}

impl<T> Service<T> for TcpForwarder
where
    T: Stream + Unpin + ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, source: T) -> Result<Self::Output, Self::Error> {
        let ProxyTarget(host_with_port) = source
            .extensions()
            .get()
            .context("missing forward authority")?;

        let extensions = source.extensions().clone();
        let mut tcp_req = Request::new_with_extensions(host_with_port.clone(), extensions);

        let target = match &self.kind {
            ForwarderKind::Direct(connector) => {
                let EstablishedClientConnection { conn: target, .. } = connector
                    .connect(tcp_req)
                    .await
                    .context("establish direct tcp connection")
                    .with_context_field("target", || host_with_port.clone())?;
                Either::A(target)
            }
            ForwarderKind::Proxied {
                connector,
                proxy_addr,
            } => {
                tcp_req.extensions_mut().insert(proxy_addr.clone());
                let EstablishedClientConnection { conn: target, .. } = connector
                    .connect(tcp_req)
                    .await
                    .context("establish proxied tcp connection")
                    .with_context_field("proxy", || proxy_addr.clone())
                    .with_context_field("target", || host_with_port.clone())?;
                Either::B(target)
            }
        };

        let proxy_req = ProxyRequest { source, target };

        StreamForwardService::default().serve(proxy_req).await
    }
}
