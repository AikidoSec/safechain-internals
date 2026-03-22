use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock},
};

use rama::{
    Layer, Service,
    cli::service::echo::EchoServiceBuilder,
    dns::client::{
        EmptyDnsResolver,
        resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver},
    },
    error::BoxError,
    extensions::ExtensionsMut,
    http::{
        Request, Response,
        layer::{map_response_body::MapResponseBodyLayer, trace::TraceLayer},
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{WebService, response::IntoResponse},
    },
    io::Io,
    layer::ArcLayer,
    net::{
        address::{Domain, SocketAddress},
        client::ConnectorService,
        tls::{
            ApplicationProtocol,
            server::{SelfSignedData, ServerAuth, ServerConfig, TlsPeekRouter},
        },
        transport::TryRefIntoTransportContext,
    },
    rt::Executor,
    service::service_fn,
    tcp::{
        TcpStream,
        client::{TcpStreamConnector, service::TcpConnector},
        server::TcpListener,
    },
    telemetry::tracing,
    tls::boring::server::TlsAcceptorLayer,
};
use safechain_proxy_lib::utils::env::aikido_app_base_url;

use crate::utils::PEEK_TIMEOUT;

mod assert_endpoint;
mod endpoint_protection_callbacks;
mod malware_list;
mod npm_registry;
mod vscode_marketplace;

fn mock_server_addr() -> SocketAddress {
    static MOCK_SERVER_ADDR: LazyLock<SocketAddress> = LazyLock::new(spawn_mock_server);
    *MOCK_SERVER_ADDR
}

#[inline(always)]
pub(super) fn new_mock_dns_resolver() -> impl DnsResolver {
    MockDnsResolver {
        ip: mock_server_addr().ip_addr,
        empty: EmptyDnsResolver::new(),
    }
}

#[derive(Debug, Clone)]
struct MockDnsResolver {
    ip: IpAddr,
    empty: EmptyDnsResolver,
}

impl DnsAddressResolver for MockDnsResolver {
    type Error = <IpAddr as DnsAddressResolver>::Error;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl rama::stream::Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
        self.ip.lookup_ipv4(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl rama::stream::Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
        self.ip.lookup_ipv6(domain)
    }
}

impl DnsTxtResolver for MockDnsResolver {
    type Error = <EmptyDnsResolver as DnsTxtResolver>::Error;

    #[inline(always)]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl rama::stream::Stream<Item = Result<rama::bytes::Bytes, Self::Error>> + Send + '_ {
        self.empty.lookup_txt(domain)
    }
}

impl DnsResolver for MockDnsResolver {}

/// Create a TCP [`ConnectorService`] accessing the mock server, spawned once.
pub fn new_mock_tcp_connector<Input>(
    exec: Executor,
) -> impl ConnectorService<Input, Connection: Io + Unpin> + Clone
where
    Input:
        ExtensionsMut + TryRefIntoTransportContext<Error: Send + Sync + 'static> + Send + 'static,
    BoxError: From<Input::Error>,
{
    let socket_addr = mock_server_addr();
    TcpConnector::new(exec)
        .with_connector(MockTcpConnectorService(socket_addr))
        .with_dns(socket_addr.ip_addr)
}

#[derive(Debug, Clone)]
struct MockTcpConnectorService(SocketAddress);

impl TcpStreamConnector for MockTcpConnectorService {
    type Error = std::io::Error;

    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let overwrite = self.0.into();
        tracing::info!(
            "MockTcpConnectorService: connect to hardcoded addr {overwrite} instead of requested {addr}"
        );
        let stream = ().connect(overwrite).await?;
        tracing::info!(
            "MockTcpConnectorService: stream established for hardcoded addr {overwrite}"
        );
        Ok(stream)
    }
}

static ASSERT_ENDPOINT_STATE: LazyLock<assert_endpoint::MockState> =
    LazyLock::new(assert_endpoint::MockState::new);

fn spawn_mock_server() -> SocketAddress {
    let std_tcp_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("to bind mock tcp server");
    let tcp_listener =
        TcpListener::try_from_std_tcp_listener(std_tcp_listener, Executor::default())
            .expect("convert std listener into rama-compatible listener");

    let addr = tcp_listener.local_addr().expect("to get local address");

    let http_server = HttpServer::auto(Executor::default()).service(new_mock_server());

    let tls_acceptor_data = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
            organisation_name: Some("Mock (test) Tls Acceptor".to_owned()),
            ..Default::default()
        }))
    }
    .try_into()
    .expect("create tls server config");

    let https_server = TlsPeekRouter::new(
        TlsAcceptorLayer::new(tls_acceptor_data).into_layer(http_server.clone()),
    )
    .with_fallback(http_server)
    .with_peek_timeout(PEEK_TIMEOUT);

    std::thread::spawn(move || {
        let tokio_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime for separate std thread to be used for mock server");
        tokio_rt.block_on(async move {
            tracing::info!("mock server is listening @ {addr}...");
            tcp_listener.serve(https_server).await
        });
    });

    addr.into()
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
