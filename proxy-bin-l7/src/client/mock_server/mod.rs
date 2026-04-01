use std::{
    convert::Infallible,
    sync::{Arc, LazyLock},
};

use rama::{
    Layer, Service,
    cli::service::echo::EchoServiceBuilder,
    error::BoxError,
    extensions::ExtensionsMut,
    http::{
        Request, Response,
        layer::{
            compression::CompressionLayer, map_response_body::MapResponseBodyLayer,
            trace::TraceLayer,
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{WebService, response::IntoResponse},
    },
    io::Io,
    layer::ArcLayer,
    net::{
        address::Domain,
        client::ConnectorService,
        test_utils::client::{MockConnectorService, MockSocket},
        tls::{
            ApplicationProtocol,
            server::{
                SelfSignedData, ServerAuth, ServerCertIssuerData, ServerCertIssuerKind,
                ServerConfig, TlsPeekRouter,
            },
        },
        transport::TryRefIntoTransportContext,
    },
    rt::Executor,
    service::{BoxService, service_fn},
    telemetry::tracing,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};
use safechain_proxy_lib::utils::env::aikido_app_base_url;

use crate::utils::PEEK_TIMEOUT;

mod assert_endpoint;
mod endpoint_protection_callbacks;
pub mod malware_list;
mod npm_registry;
mod vscode_marketplace;

/// Create a TCP [`ConnectorService`] accessing the mock server, spawned once.
pub fn new_mock_tcp_connector<Input>(
    exec: Executor,
) -> impl ConnectorService<Input, Connection: Io + Unpin> + Clone
where
    Input:
        ExtensionsMut + TryRefIntoTransportContext<Error: Send + Sync + 'static> + Send + 'static,
    BoxError: From<Input::Error>,
{
    // Use an in-memory duplex stream pair instead of binding a real TCP socket.
    // This keeps the mock transport deterministic and avoids sandbox/socket flakiness.
    let mut connector =
        MockConnectorService::new(new_mock_transport_server).with_max_buffer_size(64 * 1024);
    connector.set_executor(exec);
    connector
}

static ASSERT_ENDPOINT_STATE: LazyLock<assert_endpoint::MockState> =
    LazyLock::new(assert_endpoint::MockState::new);

fn new_mock_transport_server() -> impl Service<MockSocket, Output = (), Error = BoxError> {
    static SERVER: LazyLock<BoxService<MockSocket, (), BoxError>> = LazyLock::new(|| {
        let http_server = HttpServer::auto(Executor::default()).service(new_mock_server());
        let tls_acceptor_data = new_tls_acceptor_data();

        TlsPeekRouter::new(TlsAcceptorLayer::new(tls_acceptor_data).into_layer(http_server.clone()))
            .with_fallback(http_server)
            .with_peek_timeout(PEEK_TIMEOUT)
            .boxed()
    });

    SERVER.clone()
}

fn new_tls_acceptor_data() -> TlsAcceptorData {
    ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
            kind: ServerCertIssuerKind::SelfSigned(SelfSignedData {
                organisation_name: Some("Mock (test) Tls Acceptor".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
    .try_into()
    .expect("create tls server config")
}

fn new_mock_server() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let echo_svc_builder = EchoServiceBuilder::default();
    let echo_svc = Arc::new(echo_svc_builder.build_http(Executor::default()));
    let not_found_svc = service_fn(move |req| {
        let echo_svc = echo_svc.clone();
        async move { echo_svc.serve(req).await.map(IntoResponse::into_response) }
    });

    let app_domain = app_domain_from_base_url();

    let mock_server = WebService::new()
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("malware-list.aikido.dev")),
            self::malware_list::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("marketplace.visualstudio.com")),
            self::vscode_marketplace::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("registry.npmjs.org")),
            self::npm_registry::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(app_domain),
            self::endpoint_protection_callbacks::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("assert-test.internal")),
            self::assert_endpoint::web_svc(ASSERT_ENDPOINT_STATE.clone()),
        )
        // echo all non-blocked requests back
        .with_not_found(not_found_svc);

    tracing::warn!(
        "Mock (web) server created: do not use in production, only meant for automated testing!"
    );

    (
        ArcLayer::new(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        CompressionLayer::new(),
        TraceLayer::new_for_http(),
    )
        .into_layer(mock_server)
}

fn app_domain_from_base_url() -> Domain {
    let base_url = aikido_app_base_url();
    let host = base_url
        .host()
        .expect("aikido app base URL should always have a host");
    host.parse::<Domain>()
        .expect("aikido app base URL host should be a valid domain")
}
