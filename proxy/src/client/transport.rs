use rama::{
    dns::GlobalDnsResolver,
    rt::Executor,
    tcp::{self, client::service::TcpStreamConnectorCloneFactory},
};

pub type TcpConnector = tcp::client::service::TcpConnector<
    GlobalDnsResolver,
    TcpStreamConnectorCloneFactory<TcpStreamConnector>,
>;

pub fn new_tcp_connector(exec: Executor) -> TcpConnector {
    tcp::client::service::TcpConnector::new(exec).with_connector(TcpStreamConnector::new())
}

#[cfg(not(any(test, feature = "bench")))]
mod production {
    use std::sync::Arc;

    use rama::tls::boring::client::TlsConnectorDataBuilder;

    #[derive(Debug, Clone)]
    pub struct TcpStreamConnector;

    impl TcpStreamConnector {
        #[inline(always)]
        pub(super) fn new() -> Self {
            Self
        }
    }

    impl rama::tcp::client::TcpStreamConnector for TcpStreamConnector {
        type Error = std::io::Error;

        fn connect(
            &self,
            addr: std::net::SocketAddr,
        ) -> impl Future<Output = Result<rama::tcp::TcpStream, Self::Error>> + Send + '_ {
            ().connect(addr)
        }
    }

    #[inline(always)]
    pub fn new_tls_connector_config() -> Option<Arc<TlsConnectorDataBuilder>> {
        None
    }
}

#[cfg(not(any(test, feature = "bench")))]
pub use self::production::{TcpStreamConnector, new_tls_connector_config};

#[cfg(any(test, feature = "bench"))]
mod bench {
    use std::sync::{Arc, OnceLock};

    use rama::{
        error::OpaqueError,
        net::{address::SocketAddress, tls::client::ServerVerifyMode},
        telemetry::tracing,
        tls::boring::client::TlsConnectorDataBuilder,
    };

    static EGRESS_ADDRESS_OVERWRITE: OnceLock<Option<SocketAddress>> = OnceLock::new();

    pub fn try_set_egress_address_overwrite(address: SocketAddress) -> Result<(), OpaqueError> {
        EGRESS_ADDRESS_OVERWRITE
            .set(Some(address))
            .map_err(|v| OpaqueError::from_display(format!("egress address already set: {v:?}")))
    }

    fn get_egress_address_overwrite() -> Option<SocketAddress> {
        *EGRESS_ADDRESS_OVERWRITE.get_or_init(Default::default)
    }

    fn is_eggress_address_overwritten() -> bool {
        get_egress_address_overwrite().is_some()
    }

    #[derive(Debug, Clone)]
    pub struct TcpStreamConnector(Option<SocketAddress>);

    impl TcpStreamConnector {
        #[inline(always)]
        pub(super) fn new() -> Self {
            Self(get_egress_address_overwrite())
        }
    }

    impl rama::tcp::client::TcpStreamConnector for TcpStreamConnector {
        type Error = std::io::Error;

        async fn connect(
            &self,
            addr: std::net::SocketAddr,
        ) -> Result<rama::tcp::TcpStream, Self::Error> {
            match self.0 {
                Some(overwrite_addr) => {
                    tracing::debug!("tcp connect addr = {addr} hijack w/ addr: {overwrite_addr}");
                    ().connect(overwrite_addr.into()).await
                }
                None => ().connect(addr).await,
            }
        }
    }

    #[inline(always)]
    pub fn new_tls_connector_config() -> Option<Arc<TlsConnectorDataBuilder>> {
        is_eggress_address_overwritten().then(|| {
            Arc::new(
                TlsConnectorDataBuilder::new_http_auto()
                    .with_server_verify_mode(ServerVerifyMode::Disable),
            )
        })
    }
}

#[cfg(any(test, feature = "bench"))]
pub use self::bench::{
    TcpStreamConnector, new_tls_connector_config, try_set_egress_address_overwrite,
};
