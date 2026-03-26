use std::time::Duration;

use moka::Equivalent;
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::{self, ExtensionsMut},
    io::{BridgeIo, Io},
    net::{
        address::Domain,
        proxy::IoForwardService,
        tls::{client::ClientHelloExtension, server::InputWithClientHello},
    },
    telemetry::tracing,
    tls::boring::{
        TlsStream,
        proxy::{TlsMitmRelayService, cert_issuer::BoringMitmCertIssuer},
    },
    utils::str::smol_str::{SmolStr, ToSmolStr},
};

use crate::{
    http::firewall::{Firewall, events::TlsTerminationFailedEvent},
    utils::net::get_app_source_bundle_id_from_ext,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    sni: Domain,
    app: Option<SmolStr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKeyRef<'a> {
    sni: &'a Domain,
    app: Option<&'a str>,
}

impl<'a> Equivalent<CacheKey> for CacheKeyRef<'a> {
    fn equivalent(&self, key: &CacheKey) -> bool {
        self.sni == &key.sni && self.app == key.app.as_deref()
    }
}

type Cache = moka::sync::Cache<CacheKey, ()>;

#[derive(Debug, Clone)]
pub struct TlsMitmRelayPolicyLayer {
    cache: Cache,
    firewall: Firewall,
    mitm_all: bool,
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
            mitm_all: false,
            fallback: IoForwardService::new(),
        }
    }

    rama::utils::macros::generate_set_and_with! {
        /// Configure the policy to MITM _all_ traffic,
        /// even if not required by the firewall.
        pub fn mitm_all(mut self, all: bool) -> Self {
            self.mitm_all = all;
            self
        }
    }
}

impl<Issuer, Inner> Layer<TlsMitmRelayService<Issuer, Inner>> for TlsMitmRelayPolicyLayer {
    type Service = TlsMitmRelayPolicyService<Issuer, Inner>;

    fn layer(&self, tls_relay: TlsMitmRelayService<Issuer, Inner>) -> Self::Service {
        let Self {
            cache,
            firewall,
            mitm_all,
            fallback,
        } = self;

        Self::Service {
            cache: cache.clone(),
            firewall: firewall.clone(),
            mitm_all: *mitm_all,
            fallback: fallback.clone(),
            tls_relay,
        }
    }

    fn into_layer(self, tls_relay: TlsMitmRelayService<Issuer, Inner>) -> Self::Service {
        let Self {
            cache,
            firewall,
            mitm_all,
            fallback,
        } = self;

        Self::Service {
            cache,
            firewall,
            mitm_all,
            fallback,
            tls_relay,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsMitmRelayPolicyService<Issuer, Inner> {
    cache: Cache,
    firewall: Firewall,
    mitm_all: bool,
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
            input: mut bridge_io,
            client_hello,
        }: InputWithClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<Self::Output, Self::Error> {
        let maybe_server_name = client_hello.ext_server_name().cloned();
        let source_app_bundle_id =
            get_app_source_bundle_id_from_ext(&bridge_io).map(|s| s.to_smolstr());

        if client_hello
            .extensions()
            .iter()
            .any(|ext| matches!(ext, ClientHelloExtension::EncryptedClientHello(_)))
        {
            tracing::debug!(
                ?source_app_bundle_id,
                "ingress TLS handshake contains ECH, plain-text server name might be missing or invalid; SNI = {maybe_server_name:?}"
            )
        }

        if let Some(server_name) = maybe_server_name {
            match self.firewall.match_http_rules(&server_name) {
                Some(http_rules) => {
                    // insert the http rules so that they can be used after tls handshake for ws & for our fw layer
                    bridge_io.extensions_mut().insert(http_rules);
                }
                None if self.mitm_all => (),
                None => {
                    tracing::debug!(
                        ?source_app_bundle_id,
                        "serving via fallback IO due to no firewall rule being mached; SNI = {server_name}"
                    );
                    let server_name = server_name.clone();
                    return self
                        .fallback
                        .serve(bridge_io)
                        .await
                        .context(
                            "serve via fallback IO (skip TLS due to present in exclusion list)",
                        )
                        .context_field("sni", server_name);
                }
            }

            if self
                .cache
                .get(&CacheKeyRef {
                    sni: &server_name,
                    app: source_app_bundle_id.as_deref(),
                })
                .is_some()
            {
                tracing::debug!(
                    ?source_app_bundle_id,
                    "serving via fallback IO due to exception in cache for SNI = {server_name}"
                );
                return self
                    .fallback
                    .serve(bridge_io)
                    .await
                    .context("serve via fallback IO (skip TLS due to cached exception)")
                    .context_field("sni", server_name);
            }
        } else if !self.mitm_all {
            tracing::debug!(
                ?source_app_bundle_id,
                "serving via fallback IO due to no SNI found",
            );
            return self
                .fallback
                .serve(bridge_io)
                .await
                .context("serve via fallback IO (skip TLS due to no SNI found)");
        }

        tracing::debug!(
            ?source_app_bundle_id,
            mitm_all = self.mitm_all,
            "tls-MITM traffic",
        );
        if let Err(err) = self
            .tls_relay
            .serve(InputWithClientHello {
                input: bridge_io,
                client_hello,
            })
            .await
        {
            if err.is_handshake_relay_issue()
                && let Some(sni) = err.sni().cloned()
            {
                tracing::debug!(
                    ?source_app_bundle_id,
                    %sni,
                    %err,
                    "adding SNI exception for follow-up tls relay inputs due to Handshake Relay Issue"
                );

                self.firewall
                    .record_tls_termination_failed(TlsTerminationFailedEvent {
                        ts_ms: rama::utils::time::now_unix_ms(),
                        sni: sni.to_string(),
                        app: source_app_bundle_id.as_deref().map(String::from),
                        error: err.to_string(),
                    });

                self.cache.insert(
                    CacheKey {
                        sni,
                        app: source_app_bundle_id.clone(),
                    },
                    (),
                );
            }

            let sni = err.sni().cloned();
            return Err(err
                .context("serve via tls relay")
                .context_debug_field("sni", sni)
                .context_debug_field("app", source_app_bundle_id));
        }

        Ok(())
    }
}
