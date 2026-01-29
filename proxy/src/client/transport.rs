use rama::{
    dns::GlobalDnsResolver,
    rt::Executor,
    tcp::{self, client::service::TcpStreamConnectorCloneFactory},
};

pub type TcpConnector = tcp::client::service::TcpConnector<
    GlobalDnsResolver,
    TcpStreamConnectorCloneFactory<TcpStreamConnector>,
>;

#[derive(Debug, Default)]
pub struct TcpConnectorConfig {
    #[cfg(all(not(test), feature = "bench"))]
    pub do_not_allow_overwrite: bool,
}

pub fn new_tcp_connector(exec: Executor, cfg: TcpConnectorConfig) -> TcpConnector {
    tcp::client::service::TcpConnector::new(exec).with_connector(TcpStreamConnector::new(cfg))
}

#[cfg(not(any(test, feature = "bench")))]
mod production {
    use rama::{error::OpaqueError, tls::rustls::client::TlsConnectorData};

    #[derive(Debug, Clone)]
    pub struct TcpStreamConnector;

    impl TcpStreamConnector {
        #[inline(always)]
        pub(super) fn new(_cfg: super::TcpConnectorConfig) -> Self {
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
    pub fn new_tls_connector_config() -> Result<TlsConnectorData, OpaqueError> {
        TlsConnectorData::try_new_http_auto()
    }
}

#[cfg(not(any(test, feature = "bench")))]
pub use self::production::{TcpStreamConnector, new_tls_connector_config};

#[cfg(any(test, feature = "bench"))]
mod bench {
    use std::sync::OnceLock;

    use rama::{
        error::{ErrorContext as _, OpaqueError},
        net::address::SocketAddress,
        telemetry::tracing,
        tls::rustls::{
            client::{TlsConnectorData, TlsConnectorDataBuilder},
            dep::rustls::ClientConfig,
        },
    };

    use rustls_platform_verifier::ConfigVerifierExt as _;

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
        pub(super) fn new(cfg: super::TcpConnectorConfig) -> Self {
            tracing::trace!("TcpStreamConnector w/ cfg: {cfg:?}");

            #[cfg(all(not(test), feature = "bench"))]
            if cfg.do_not_allow_overwrite {
                return Self(None);
            }

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
    pub fn new_tls_connector_config() -> Result<TlsConnectorData, OpaqueError> {
        if is_eggress_address_overwritten() {
            Ok(TlsConnectorDataBuilder::new()
                .with_alpn_protocols_http_auto()
                .with_no_cert_verifier()
                .build())
        } else {
            let config =
                ClientConfig::with_platform_verifier().context("create platform verifier")?;
            Ok(config.into())
        }
    }
}

#[cfg(any(test, feature = "bench"))]
pub use self::bench::{
    TcpStreamConnector, new_tls_connector_config, try_set_egress_address_overwrite,
};
