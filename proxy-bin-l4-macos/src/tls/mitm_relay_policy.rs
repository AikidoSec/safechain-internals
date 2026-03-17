use std::time::Duration;

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::{self, ExtensionsRef},
    io::{BridgeIo, Io},
    net::{
        address::{Domain, Host},
        proxy::{IoForwardService, ProxyTarget},
        tls::{client::ClientHelloExtension, server::InputWithClientHello},
    },
    telemetry::tracing,
    tls::boring::{
        TlsStream,
        proxy::{TlsMitmRelayService, cert_issuer::BoringMitmCertIssuer},
    },
};
use safechain_proxy_lib::http::firewall::Firewall;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PolicyKey {
    Sni(Domain),
    Target(Host),
}

type Cache = moka::sync::Cache<PolicyKey, ()>;

#[derive(Debug, Clone)]
pub struct TlsMitmRelayPolicyLayer {
    cache: Cache,
    firewall: Firewall,
    fallback: IoForwardService,
}

impl TlsMitmRelayPolicyLayer {
    #[inline(always)]
    pub fn new(firewall: Firewall) -> Self {
        let cache = moka::sync::CacheBuilder::new(4096)
            .time_to_live(Duration::from_mins(5))
            .build();
        Self {
            cache,
            firewall,
            fallback: IoForwardService::new(),
        }
    }
}

impl<Issuer, Inner> Layer<TlsMitmRelayService<Issuer, Inner>> for TlsMitmRelayPolicyLayer {
    type Service = TlsMitmRelayPolicyService<Issuer, Inner>;

    fn layer(&self, tls_relay: TlsMitmRelayService<Issuer, Inner>) -> Self::Service {
        let Self {
            cache,
            firewall,
            fallback,
        } = self;

        Self::Service {
            cache: cache.clone(),
            firewall: firewall.clone(),
            fallback: fallback.clone(),
            tls_relay,
        }
    }

    fn into_layer(self, tls_relay: TlsMitmRelayService<Issuer, Inner>) -> Self::Service {
        let Self {
            cache,
            firewall,
            fallback,
        } = self;

        Self::Service {
            cache,
            firewall,
            fallback,
            tls_relay,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsMitmRelayPolicyService<Issuer, Inner> {
    cache: Cache,
    firewall: Firewall,
    fallback: IoForwardService,
    tls_relay: TlsMitmRelayService<Issuer, Inner>,
}

impl<Issuer, Inner, Ingress, Egress> Service<InputWithClientHello<BridgeIo<Ingress, Egress>>>
    for TlsMitmRelayPolicyService<Issuer, Inner>
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>>,
    Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Output = (), Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsMut,
    Egress: Io + Unpin + extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        InputWithClientHello {
            input: bridge_io,
            client_hello,
        }: InputWithClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<Self::Output, Self::Error> {
        let maybe_server_name = client_hello.ext_server_name().cloned();

        if client_hello
            .extensions()
            .iter()
            .any(|ext| matches!(ext, ClientHelloExtension::EncryptedClientHello(_)))
        {
            tracing::debug!(
                "ingress TLS handshake contains ECH, plain-text server name might be missing or invalid; SNI = {maybe_server_name:?}"
            )
        }

        if let Some(server_name) = maybe_server_name {
            if !self.firewall.match_domain(&server_name) {
                tracing::debug!(
                    "serving via fallback IO due to no firewall rule being mached; SNI = {server_name}"
                );
                let server_name = server_name.clone();
                return self
                    .fallback
                    .serve(bridge_io)
                    .await
                    .context("serve via fallback IO (skip TLS due to present in exclusion list)")
                    .context_field("sni", server_name);
            }

            if self
                .cache
                .get(&PolicyKey::Sni(server_name.clone()))
                .is_some()
            {
                tracing::debug!(
                    "serving via fallback IO due to exception in cache for SNI = {server_name}"
                );
                return self
                    .fallback
                    .serve(bridge_io)
                    .await
                    .context("serve via fallback IO (skip TLS due to cached exception)")
                    .context_field("sni", server_name);
            }
        }

        if let Some(ProxyTarget(target)) = bridge_io.extensions().get().cloned()
            && self
                .cache
                .get(&PolicyKey::Target(target.host.clone()))
                .is_some()
        {
            tracing::debug!(
                "serving via fallback IO due to exception in cache for ProxyTarget = {target}"
            );
            return self
                .fallback
                .serve(bridge_io)
                .await
                .context("serve via fallback IO (skip TLS due to cached exception)")
                .context_field("proxy_target", target);
        }

        if let Err(err) = self
            .tls_relay
            .serve(InputWithClientHello {
                input: bridge_io,
                client_hello,
            })
            .await
            && err.is_relay_cert_issue()
        {
            if let Some(sni) = err.sni().cloned() {
                tracing::debug!(
                    "adding SNI ({sni}) exception for follow-up tls relay inputs due to Relay Cert Issue"
                );
                self.cache.insert(PolicyKey::Sni(sni), ());
            }
            if let Some(target) = err.proxy_target() {
                tracing::debug!(
                    "adding ProxyTarget ({target}) exception for follow-up tls relay inputs due to Relay Cert Issue"
                );
                self.cache
                    .insert(PolicyKey::Target(target.host.clone()), ());
            }

            return Err(err.context("serve via tls relay"));
        }

        Ok(())
    }
}
