use rama::{
    rt::Executor,
    tcp::{self, client::service::TcpStreamConnectorCloneFactory},
};

pub type TcpConnector = tcp::client::service::TcpConnector<
    DnsResolver,
    TcpStreamConnectorCloneFactory<TcpStreamConnector>,
>;

#[derive(Debug, Clone, Default)]
pub struct TcpConnectorConfig {
    #[cfg(all(not(test), feature = "bench"))]
    pub do_not_allow_overwrite: bool,
}

pub fn new_tcp_connector(exec: Executor, cfg: TcpConnectorConfig) -> TcpConnector {
    tcp::client::service::TcpConnector::new(exec)
        .with_connector(TcpStreamConnector::new(cfg.clone()))
        .with_dns(new_dns_resolver(cfg))
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

    pub use ::rama::dns::GlobalDnsResolver as DnsResolver;

    #[inline(always)]
    pub fn new_dns_resolver(_cfg: super::TcpConnectorConfig) -> DnsResolver {
        DnsResolver::new()
    }

    #[inline(always)]
    pub fn new_tls_connector_config() -> Result<TlsConnectorData, OpaqueError> {
        TlsConnectorData::try_new_http_auto()
    }
}

#[cfg(not(any(test, feature = "bench")))]
pub use self::production::{
    DnsResolver, TcpStreamConnector, new_dns_resolver, new_tls_connector_config,
};

#[cfg(any(test, feature = "bench"))]
mod bench {
    use std::sync::OnceLock;

    use rama::{
        error::{BoxError, ErrorContext as _, OpaqueError},
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

    #[derive(Debug, Clone)]
    pub struct DnsResolver(Option<::rama::dns::GlobalDnsResolver>);

    #[inline(always)]
    pub fn new_dns_resolver(cfg: super::TcpConnectorConfig) -> DnsResolver {
        tracing::trace!("DnsResolver w/ tcp cfg: {cfg:?}");

        #[cfg(all(not(test), feature = "bench"))]
        if cfg.do_not_allow_overwrite {
            // if not overwritten we do need the real DNS..
            return DnsResolver(Some(::rama::dns::GlobalDnsResolver::new()));
        }

        if is_eggress_address_overwritten() {
            DnsResolver(None)
        } else {
            DnsResolver(Some(::rama::dns::GlobalDnsResolver::new()))
        }
    }

    impl ::rama::dns::DnsResolver for DnsResolver {
        type Error = BoxError;

        async fn txt_lookup(
            &self,
            domain: rama::net::address::Domain,
        ) -> Result<Vec<Vec<u8>>, Self::Error> {
            if let Some(resolver) = self.0.as_ref() {
                resolver.txt_lookup(domain).await
            } else {
                Ok(Vec::default())
            }
        }

        async fn ipv4_lookup(
            &self,
            domain: rama::net::address::Domain,
        ) -> Result<Vec<std::net::Ipv4Addr>, Self::Error> {
            if let Some(resolver) = self.0.as_ref() {
                resolver.ipv4_lookup(domain).await
            } else {
                // dummy value, we do not connect to it anyway
                Ok(vec![std::net::Ipv4Addr::LOCALHOST])
            }
        }

        async fn ipv6_lookup(
            &self,
            domain: rama::net::address::Domain,
        ) -> Result<Vec<std::net::Ipv6Addr>, Self::Error> {
            if let Some(resolver) = self.0.as_ref() {
                resolver.ipv6_lookup(domain).await
            } else {
                // dummy value, we do not connect to it anyway
                Ok(vec![std::net::Ipv6Addr::LOCALHOST])
            }
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
    DnsResolver, TcpStreamConnector, new_dns_resolver, new_tls_connector_config,
    try_set_egress_address_overwrite,
};
