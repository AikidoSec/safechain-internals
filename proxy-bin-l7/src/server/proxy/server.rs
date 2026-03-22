use std::{convert::Infallible, sync::Arc};

use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Request, Response,
        client::{ProxyConnector, proxy::layer::HttpProxyConnectorLayer},
        layer::{
            compression::stream::StreamCompressionLayer,
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            trace::TraceLayer,
            upgrade::{
                HttpProxyConnectRelayServiceRequestMatcher, mitm::HttpUpgradeMitmRelayLayer,
            },
        },
        matcher::DomainMatcher,
        proxy::mitm::HttpMitmRelay,
        ws::handshake::matcher::HttpWebSocketRelayServiceRequestMatcher,
    },
    io::Io,
    layer::{AddInputExtensionLayer, ArcLayer, ConsumeErrLayer, HijackLayer, MapErrLayer},
    net::{
        address::ProxyAddress, http::server::HttpPeekRouter, proxy::IoForwardService,
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::Socks5ProxyConnectorLayer,
    rt::Executor,
    tcp::proxy::IoToProxyBridgeIoLayer,
    tls::boring::proxy::TlsMitmRelay,
};

use crate::{client::new_tcp_connector_service_for_proxy, utils::PEEK_TIMEOUT};

#[cfg(feature = "har")]
use ::{
    rama::{http::layer::har::extensions::RequestComment, utils::str::arcstr::arcstr},
    safechain_proxy_lib::diagnostics::har::HARExportLayer,
};

use safechain_proxy_lib::{
    http::{
        firewall::Firewall,
        service::hijack::{self, HIJACK_DOMAIN},
    },
    tls::{RootCaKeyPair, mitm_relay_policy::TlsMitmRelayPolicyLayer},
};

pub(super) fn new_app_mitm_server<S: Io + ExtensionsMut + Unpin>(
    guard: ShutdownGuard,
    mitm_all: bool,
    root_ca: RootCaKeyPair,
    upstream_proxy_address: Option<ProxyAddress>,
    firewall: Firewall,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> Result<impl Service<S, Output = (), Error = Infallible> + Clone, BoxError> {
    let exec = Executor::graceful(guard);

    let ca_crt_pem_bytes: &[u8] = root_ca
        .certificate_pem()
        .as_ref()
        .as_bytes()
        .to_vec()
        .leak();

    let (ca_crt, ca_key) = root_ca.into_pair();

    let tls_mitm_relay_policy =
        TlsMitmRelayPolicyLayer::new(firewall.clone()).with_mitm_all(mitm_all);
    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);

    let http_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware(http_relay_middleware(
        exec.clone(),
        firewall,
        ca_crt_pem_bytes,
        #[cfg(feature = "har")]
        har_export_layer,
    ));

    let maybe_http_service = HttpPeekRouter::new(http_relay)
        .with_fallback(IoForwardService::new())
        .with_peek_timeout(PEEK_TIMEOUT);

    let transport_service = PeekTlsClientHelloService::new(
        (tls_mitm_relay_policy, tls_mitm_relay).into_layer(maybe_http_service.clone()),
    )
    .with_fallback(maybe_http_service);

    let transport_middleware = (
        ConsumeErrLayer::trace_as_debug(),
        upstream_proxy_address.map(AddInputExtensionLayer::new),
        IoToProxyBridgeIoLayer::extension_proxy_target_with_connector(ProxyConnector::optional(
            new_tcp_connector_service_for_proxy(exec),
            Socks5ProxyConnectorLayer::required(),
            HttpProxyConnectorLayer::required(),
        )),
    );

    Ok(transport_middleware.into_layer(transport_service))
}

pub fn http_relay_middleware<S>(
    exec: Executor,
    firewall: Firewall,
    ca_crt_pem_bytes: &'static [u8],
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> impl Layer<S, Service: Service<Request, Output = Response, Error = BoxError> + Clone>
+ Send
+ Sync
+ 'static
+ Clone
where
    S: Service<Request, Output = Response>,
    BoxError: From<S::Error>,
{
    (
        ArcLayer::new(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        TraceLayer::new_for_http(),
        StreamCompressionLayer::new(),
        #[cfg(feature = "har")]
        (
            AddInputExtensionLayer::new(RequestComment(arcstr!("http(s) MITM server"))),
            har_export_layer,
        ),
        HijackLayer::new(
            DomainMatcher::exact(HIJACK_DOMAIN),
            Arc::new(hijack::new_service(ca_crt_pem_bytes)),
        ),
        firewall.clone().into_evaluate_response_layer(),
        firewall.into_evaluate_request_layer(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        DecompressionLayer::new(),
        HttpUpgradeMitmRelayLayer::new(
            exec,
            (
                HttpWebSocketRelayServiceRequestMatcher::new(
                    // NOTE: change service of HttpWebSocketRelayServiceRequestMatcher with WS MitmRelay
                    // if you ever want to inspect Websocket traffic :)
                    ConsumeErrLayer::trace_as_debug().into_layer(IoForwardService::new()),
                ),
                // Entering an HTTP CONNECT would mean the client
                // opens an HTTP CONNECT tunnel within a SOCKS5/HTTP tunnel...
                // possible, but ... rare and weird
                HttpProxyConnectRelayServiceRequestMatcher::new(
                    ConsumeErrLayer::trace_as_debug().into_layer(IoForwardService::new()),
                ),
            ),
        ),
        MapErrLayer::into_box_error(),
        ArcLayer::new(),
    )
}
