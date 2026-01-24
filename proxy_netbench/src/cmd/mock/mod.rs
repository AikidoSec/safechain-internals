use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

use rama::{
    Layer as _, Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsRef,
    graceful::ShutdownGuard,
    http::{
        Body, HeaderValue, InfiniteReader, Request, Response, StatusCode, Uri,
        body::util::BodyExt,
        headers::{ContentLength, ContentType, HeaderMapExt},
        layer::{
            compression::CompressionLayer, required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
        },
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{AbortableLayer, TimeoutLayer, abort::AbortController},
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
use safechain_proxy_lib::{
    firewall::malware_list::MALWARE_LIST_URI_STR_NPM, server, storage, utils,
};

use crate::{
    config::{Scenario, ServerConfig, download_malware_list_for_uri},
    http::{
        MockReplayIndex, MockResponseRandomIndex,
        har::{self, HarEntry},
    },
};

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

    /// replay the responses from the provided HAR file
    #[arg(long, value_name = "HAR_FILE_PATH")]
    pub replay: Option<PathBuf>,
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

    let merged_cfg = merge_server_cfg(args.clone());

    let http_svc = (
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        AddRequiredResponseHeadersLayer::new()
            .with_server_header_value(HeaderValue::from_static(utils::env::server_identifier())),
    )
        .into_layer(Arc::new(
            MockHttpServer::try_new(data.clone(), args.replay.clone(), merged_cfg).await?,
        ));

    let http_server = HttpServer::auto(exec).service(Arc::new(http_svc));

    let tls_acceptor = TlsAcceptorLayer::new(try_new_tls_self_signed_server_data()?);

    let tcp_svc = (
        AbortableLayer::new(),
        TimeoutLayer::new(Duration::from_secs(60)),
    )
        .into_layer(
            TlsPeekRouter::new(tls_acceptor.into_layer(http_server.clone()))
                .with_fallback(http_server),
        );

    let server_addr = tcp_listener
        .local_addr()
        .context("get bound address for mock http(s) server")?;

    // write the address right before serving
    server::write_server_socket_address_as_file(&data, "netbench.mock", server_addr.into()).await?;

    tracing::info!("mock server ready to serve @ {server_addr}");
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
    ok_responses: OkResponses,
}

impl MockHttpServer {
    async fn try_new(
        data: PathBuf,
        replay: Option<PathBuf>,
        cfg: ServerConfig,
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

        let ok_responses = match replay {
            Some(path) => OkResponses::try_new_replay(path).await?,
            None => {
                let data_storage = storage::SyncCompactDataStorage::try_new(data.clone())
                    .with_context(|| {
                        format!(
                            "create compact data storage using dir at path '{}'",
                            data.display()
                        )
                    })?;
                tracing::info!(path = ?data, "data directory ready to be used");
                OkResponses::try_new_random_payloads(data_storage).await?
            }
        };

        Ok(Self {
            base_latency,
            jitter,
            error_rate,
            drop_rate,
            timeout_rate,
            ok_responses,
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
                if let Some(controller) = req.extensions().get::<AbortController>() {
                    controller.abort().await;
                }
                tracing::error!("failed to abort connection via controller");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            MockOutcome::Timeout => StatusCode::REQUEST_TIMEOUT.into_response(),
            MockOutcome::Error => Self::error_response(),
            MockOutcome::Ok => match self.ok_responses.generate_response(&req) {
                Some(resp) => resp,
                None => {
                    if let Some(controller) = req.extensions().get::<AbortController>() {
                        controller.abort().await;
                    }
                    tracing::error!("failed to abort connection via controller");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            },
        })
    }
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

#[derive(Debug)]
enum OkResponses {
    Random(Vec<&'static [u8]>),
    Replay(Vec<HarEntry>),
}

impl OkResponses {
    async fn try_new_random_payloads(
        data_storage: storage::SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError> {
        tracing::info!("generating random OK payloads...");

        let mut ok_payloads: Vec<&'static [u8]> = Vec::with_capacity(8);
        for multiplier in 0..5 {
            let payload = InfiniteReader::new()
                .with_size_limit(2usize.pow(multiplier as u32) * 512)
                .into_body()
                .collect()
                .await
                .context("read generated random body")?
                .to_bytes();
            ok_payloads.push(payload.to_vec().leak());
        }
        // compressible payloads
        ok_payloads.push(include_bytes!("./mod.rs"));
        ok_payloads.push(include_bytes!("../../../Cargo.toml"));
        // very compressible but big payload
        ok_payloads.push(
            format!(
                "{:?}",
                download_malware_list_for_uri(data_storage, MALWARE_LIST_URI_STR_NPM).await?
            )
            .into_bytes()
            .leak(),
        );

        Ok(Self::Random(ok_payloads))
    }

    async fn try_new_replay(path: PathBuf) -> Result<Self, OpaqueError> {
        tracing::info!("generating replay responses...");
        let entries = har::load_har_entries(path).await?;
        Ok(Self::Replay(entries))
    }
}

fn random_index_from_uri(uri: &Uri, m: usize) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&uri, &mut h);
    (std::hash::Hasher::finish(&h) as usize) % m
}

impl OkResponses {
    pub fn generate_response(&self, req: &Request) -> Option<Response> {
        match self {
            OkResponses::Random(items) => {
                let index = random_index_from_uri(req.uri(), items.len());
                let payload = items[index];

                let body = if payload.is_empty() {
                    Body::empty()
                } else {
                    Body::from(payload)
                };

                let mut resp = (StatusCode::OK, body).into_response();
                resp.headers_mut()
                    .typed_insert(MockResponseRandomIndex(index));
                if !payload.is_empty() {
                    resp.headers_mut().typed_insert(ContentType::octet_stream());
                    if rand::random_bool(0.5) {
                        resp.headers_mut()
                            .typed_insert(ContentLength(payload.len() as u64));
                    }
                }

                Some(resp)
            }
            OkResponses::Replay(items) => {
                let index = match req.headers().typed_get() {
                    Some(MockReplayIndex(index)) => index % items.len(),
                    None => random_index_from_uri(req.uri(), items.len()),
                };
                items[index].response.as_ref().map(|resp| {
                    let mut resp = resp.clone_as_http_response();
                    resp.headers_mut().typed_insert(MockReplayIndex(index));
                    resp
                })
            }
        }
    }
}
