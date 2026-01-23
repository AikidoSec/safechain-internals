use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

use rama::{
    Layer as _, Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{
        Body, HeaderValue, Request, Response, StatusCode,
        headers::ContentType,
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::response::{Headers, IntoResponse},
    },
    layer::TimeoutLayer,
    net::{
        socket::Interface,
        tls::{
            self, ApplicationProtocol,
            server::{SelfSignedData, ServerAuth, TlsPeekRouter},
        },
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

use clap::Args;
use safechain_proxy_lib::{server, utils};
use tokio::sync::mpsc;

use crate::config::{Scenario, ServerConfig};

#[derive(Debug, Clone, Args)]
/// run bench mock server
pub struct MockCommand {
    #[clap(flatten)]
    config: Option<ServerConfig>,

    #[arg(long)]
    /// Scenario to run,
    /// manually defined parameters overwrite scenario parameters.
    scenario: Option<Scenario>,

    /// network interface to bind to
    #[arg(
        long,
        short = 'b',
        value_name = "INTERFACE",
        default_value = "127.0.0.1:0"
    )]
    pub bind: Interface,
}

pub async fn exec(
    data: PathBuf,
    guard: ShutdownGuard,
    args: MockCommand,
) -> Result<(), OpaqueError> {
    tokio::fs::create_dir_all(&data)
        .await
        .with_context(|| format!("create data directory at path '{}'", data.display()))?;

    let exec = Executor::graceful(guard);
    let tcp_listener = TcpListener::bind(args.bind.clone(), exec.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind proxy meta http(s) server")?;

    let merged_cfg = merge_server_cfg(args);

    // TODO: use + perhaps something better than mpsc unbounded??

    let (drop_tcp_connection_tx, drop_tcp_connection_rx) = mpsc::unbounded_channel();

    let http_svc = (
        TraceLayer::new_for_http(),
        AddRequiredResponseHeadersLayer::new()
            .with_server_header_value(HeaderValue::from_static(utils::env::project_name())),
    )
        .into_layer(Arc::new(MockHttpServer::try_new(
            merged_cfg,
            drop_tcp_connection_tx,
        )?));

    let http_server = HttpServer::auto(exec).service(Arc::new(http_svc));

    let tls_acceptor = TlsAcceptorLayer::new(try_new_tls_self_signed_server_data()?);

    let tcp_svc = TimeoutLayer::new(Duration::from_secs(60)).into_layer(
        TlsPeekRouter::new(tls_acceptor.into_layer(http_server.clone())).with_fallback(http_server),
    );

    let server_addr = tcp_listener
        .local_addr()
        .context("get bound address for mock http(s) server")?;
    server::write_server_socket_address_as_file(&data, "netbench.mock", server_addr.into()).await?;

    tcp_listener.serve(tcp_svc).await;

    Ok(())
}

fn try_new_tls_self_signed_server_data() -> Result<TlsAcceptorData, OpaqueError> {
    let tls_server_config = tls::server::ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..tls::server::ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
            organisation_name: Some("netbench mock server".to_owned()),
            ..Default::default()
        }))
    };
    tls_server_config
        .try_into()
        .context("create tls server config")
}

#[derive(Debug)]
struct MockHttpServer {
    base_latency: f64,
    jitter: f64,
    error_rate: f32,
    drop_rate: f32,
    timeout_rate: f32,
    drop_tcp_connection: mpsc::UnboundedSender<()>,
}

impl MockHttpServer {
    fn try_new(
        cfg: ServerConfig,
        drop_tcp_connection: mpsc::UnboundedSender<()>,
    ) -> Result<Self, OpaqueError> {
        let base_latency = cfg.base_latency.unwrap_or_default();
        let jitter = cfg.jitter.unwrap_or_default();
        let error_rate = cfg.error_rate.unwrap_or_default();
        let drop_rate = cfg.drop_rate.unwrap_or_default();
        let timeout_rate = cfg.timeout_rate.unwrap_or_default();

        let sum = drop_rate + timeout_rate + error_rate;
        if sum > 1. {
            return Err(OpaqueError::from_display(
                "drop_rate + timeout_rate + error_rate must be <= 1.0",
            ));
        }

        Ok(Self {
            base_latency,
            jitter,
            error_rate,
            drop_rate,
            timeout_rate,
            drop_tcp_connection,
        })
    }

    #[inline(always)]
    fn clamp_rate(v: f32) -> f32 {
        v.clamp(0., 1.0)
    }

    fn pick_outcome(&self) -> MockOutcome {
        let drop_rate = Self::clamp_rate(self.drop_rate);
        let timeout_rate = Self::clamp_rate(self.timeout_rate);
        let error_rate = Self::clamp_rate(self.error_rate);

        let r: f32 = rand::random();

        let t_drop = drop_rate;
        let t_timeout = t_drop + timeout_rate;
        let t_error = t_timeout + error_rate;

        if r < t_drop {
            MockOutcome::Drop
        } else if r < t_timeout {
            MockOutcome::Timeout
        } else if r < t_error {
            MockOutcome::Error
        } else {
            MockOutcome::Ok
        }
    }

    fn compute_delay(&self) -> std::time::Duration {
        let base = self.base_latency.max(0.0);
        let jitter = self.jitter.max(0.0);

        if jitter == 0.0 {
            return std::time::Duration::from_secs_f64(base);
        }

        let span = jitter * 2.0;
        let u: f64 = rand::random();
        let delta = (u * span) - jitter;

        let secs = (base + delta).max(0.0);
        std::time::Duration::from_secs_f64(secs)
    }

    fn random_ok_body(uri: &rama::http::Uri) -> Body {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&uri, &mut h);
        let multiplier = (std::hash::Hasher::finish(&h) as u32) % 6;

        rama::http::body::InfiniteReader::new()
            .with_size_limit(2usize.pow(multiplier) * 512)
            .into_body()
    }

    fn random_ok_response(req: &Request) -> Response {
        let body = Self::random_ok_body(req.uri());
        (
            StatusCode::OK,
            Headers::single(ContentType::octet_stream()),
            body,
        )
            .into_response()
    }

    fn error_response() -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[derive(Debug, Clone, Copy)]
enum MockOutcome {
    Drop,
    Timeout,
    Error,
    Ok,
}

impl Service<Request> for MockHttpServer {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let delay = self.compute_delay();
        if delay.as_nanos() > 0 {
            tokio::time::sleep(delay).await;
        }

        Ok(match self.pick_outcome() {
            MockOutcome::Drop => {
                if let Err(err) = self.drop_tcp_connection.send(()) {
                    tracing::error!("failed to send MockFail::DropConnection: {err}");
                }
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            MockOutcome::Timeout => StatusCode::REQUEST_TIMEOUT.into_response(),
            MockOutcome::Error => Self::error_response(),
            MockOutcome::Ok => Self::random_ok_response(&req),
        })
    }
}

#[derive(Debug)]
struct MockTcpServer<S> {
    inner: S,
    drop_tcp_connection: mpsc::UnboundedReceiver<()>,
}

fn merge_server_cfg(args: MockCommand) -> ServerConfig {
    let scenario_cfg = args
        .scenario
        .map(|s| {
            tracing::info!("use scenario to define base config: {s:?}");
            s.server_config()
        })
        .unwrap_or_else(|| {
            tracing::info!("no scenario defined, use default as base config");
            Default::default()
        });

    let overwrite_cfg = args.config.unwrap_or_default();

    macro_rules! merge_config {
        ($scenario:ident, $overwrite:ident, {$($property:ident),+ $(,)?}) => {
            ServerConfig {
                $(
                    $property: if let Some(value) = $overwrite.$property {
                        tracing::info!("property '{}': use overwrite: {value}", stringify!($property));
                        Some(value)
                    } else if let Some(value) = $scenario.$property {
                        tracing::info!("property '{}': use scenario: {value}", stringify!($property));
                        Some(value)
                    } else {
                        tracing::info!("property '{}': undefined", stringify!($property));
                        None
                    },
                )+
            }
        };
    }

    merge_config!(
        scenario_cfg, overwrite_cfg,
        {
            base_latency,
            jitter,
            error_rate,
            drop_rate,
            timeout_rate,
        }
    )
}
