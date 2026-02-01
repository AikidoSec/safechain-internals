use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};

use rama::{
    Service as _,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, body::util::BodyExt, response::Parts},
    net::{address::SocketAddress, conn::is_connection_error},
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
};

use clap::Args;
use safechain_proxy_lib::utils::env;
use tokio::{
    sync::{
        Semaphore,
        mpsc::{self, Receiver},
    },
    time::Instant,
};

use crate::{
    cmd::run::requests::{
        GeneratedRequest, RequestGenerator, RequestGeneratorMockConfig,
        RequestGeneratorReplayConfig,
    },
    config::{ClientConfig, ProductValues, Scenario, parse_product_values},
};

pub mod client;
pub mod reporter;
pub mod requests;

use self::reporter::*;

#[derive(Debug, Clone, Args)]
/// run benhmarker
pub struct RunCommand {
    /// socket address of the proxy if proxied
    /// or else the address of the target (mock) server if directly connecting.
    #[arg(value_name = "ADDRESS", required = true)]
    target: SocketAddress,

    /// run via a proxy
    #[arg(long = "proxy", default_value_t = false)]
    proxy: bool,

    /// report json instead of a human-friendly format
    #[arg(long, default_value_t = false)]
    json: bool,

    #[clap(flatten)]
    config: Option<ClientConfig>,

    /// Iteration duration
    #[arg(long, value_name = "SECONDS", default_value_t = 5.)]
    duration: f64,

    /// Warmup duration
    #[arg(long, value_name = "SECONDS", default_value_t = 1.)]
    warmup: f64,

    /// Amount of times we run through the samples
    #[arg(long, default_value_t = 3)]
    iterations: usize,

    #[arg(long, value_parser = parse_product_values)]
    /// Scenario to run,
    /// manually defined parameters overwrite scenario parameters.
    ///
    /// Not used when replaying.
    products: Option<ProductValues>,

    /// How much mock product requests generations should contain malaware.
    ///
    /// Not used when replaying.
    #[arg(long, value_name = "SECONDS", default_value_t = 0.1)]
    malware_ratio: f64,

    /// Replay the requests from the provided HAR file
    #[arg(long, value_name = "HAR_FILE_PATH")]
    replay: Option<PathBuf>,

    /// When replaying also emulate the given timings
    #[arg(long = "emulate", default_value_t = false)]
    emulate_timing: bool,

    #[arg(long)]
    /// Scenario to run,
    /// manually defined parameters overwrite scenario parameters.
    scenario: Option<Scenario>,
}

pub async fn exec(
    data: PathBuf,
    guard: ShutdownGuard,
    args: RunCommand,
) -> Result<(), OpaqueError> {
    let run_params = RunParameters::new(args.scenario, args.config, args.duration, args.warmup);

    let client = self::client::http_client(
        Executor::graceful(guard.clone()),
        args.target,
        run_params.concurrency,
        args.proxy,
    )
    .context("create HTTP(S) client")?;

    tracing::info!(?run_params, "client config parameters ready",);

    let iterations = args.iterations.max(1);

    let req_gen = new_request_generator(
        data,
        args.replay,
        args.emulate_timing,
        args.products,
        args.malware_ratio,
        iterations,
        run_params,
    )
    .await?;

    let reporter = new_reporter(args.json);

    let (result_tx, result_rx) = mpsc::channel(run_params.concurrency * 8);
    guard.spawn_task_fn(|guard| report_worker(guard, reporter, result_rx));

    run_send_and_validate_loop(guard, run_params, req_gen, client, result_tx).await
}

async fn run_send_and_validate_loop(
    guard: ShutdownGuard,
    run_params: RunParameters,
    req_gen_input: RequestGenerator,
    client: BoxService<Request, Response, OpaqueError>,
    result_tx: mpsc::Sender<ClientResult>,
) -> Result<(), OpaqueError> {
    let mut req_gen = req_gen_input;
    let mut cancelled = std::pin::pin!(guard.clone_weak().into_cancelled());

    let concurrency = Arc::new(Semaphore::new(run_params.concurrency));

    loop {
        let GeneratedRequest {
            req,
            index,
            iteration,
            warmup,
        } = tokio::select! {
            _ = cancelled.as_mut() => {
                tracing::error!("exit bench runner early: guard shutdown");
                return Ok(());
            }
            maybe_req = req_gen.next_request() => {
                let Some(req) = maybe_req else {
                    tracing::debug!("bench runner done: exit");
                    return Ok(());
                };

                req
            }
        };

        let phase = if warmup { Phase::Warmup } else { Phase::Main };

        guard.spawn_task_fn({
            let concurrency_clone = concurrency.clone();
            let client_clone = client.clone();
            let result_tx_clone = result_tx.clone();

            move |guard| {
                serve_req_validate_resp_and_report_result(
                    guard,
                    concurrency_clone,
                    client_clone,
                    req,
                    result_tx_clone,
                    ServeRequestParameters {
                        phase,
                        iteration,
                        index,
                    },
                )
            }
        });
    }
}

#[derive(Debug, Clone, Copy)]
struct ServeRequestParameters {
    phase: Phase,
    iteration: usize,
    index: usize,
}

async fn serve_req_validate_resp_and_report_result(
    guard: ShutdownGuard,
    concurrency: Arc<Semaphore>,
    client: BoxService<Request, Response, OpaqueError>,
    req: Request,
    result_tx: mpsc::Sender<ClientResult>,
    ServeRequestParameters {
        phase,
        iteration,
        index,
    }: ServeRequestParameters,
) {
    let _guard = tokio::select! {
        _ = guard.cancelled() => {
            tracing::error!("cancel wait for concurrency: guard shutdown");
            return;
        }
        guard_result = concurrency.acquire() => {
            #[allow(clippy::expect_used, reason = "see expect msg")]
            guard_result.expect("to always be able to acquire a semaphore guard")
        }
    };

    let req_start = Instant::now();
    let result = match client.serve(req).await {
        Err(err) => Err(err),
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            match body.collect().await.context("collect resp payload") {
                Err(err) => Err(err),
                Ok(_) => Ok(parts),
            }
        }
    };
    if let Err(err) = result_tx
        .send(ClientResult {
            result,
            req_start,
            phase,
            iteration,
            index,
        })
        .await
    {
        tracing::debug!("failed to send client result msg: {err}");
    }
}

async fn new_request_generator(
    data: PathBuf,
    replay: Option<PathBuf>,
    emulate_timing: bool,
    products: Option<ProductValues>,
    malware_ratio: f64,
    iterations: usize,
    RunParameters {
        target_rps,
        burst_size,
        jitter,
        request_count_per_iteration,
        request_count_per_warmup,
        ..
    }: RunParameters,
) -> Result<RequestGenerator, OpaqueError> {
    Ok(match replay {
        Some(har_fp) => RequestGenerator::new_replay_gen(RequestGeneratorReplayConfig {
            har: har_fp,
            iterations,
            target_rps,
            burst_size,
            jitter,
            emulate_timing,
        })
        .await
        .context("create replay req generator")?,
        None => RequestGenerator::new_mock_gen(RequestGeneratorMockConfig {
            data,
            iterations,
            target_rps,
            burst_size,
            jitter,
            request_count_per_iteration,
            request_count_per_warmup,
            products,
            malware_ratio,
        })
        .await
        .context("create mock req generator")?,
    })
}

fn new_reporter(json: bool) -> Box<dyn Reporter> {
    const REPORT_INTERVAL: Duration = Duration::from_secs(1);

    if json {
        const EMIT_EVENTS: bool = true;
        Box::new(JsonlReporter::new(REPORT_INTERVAL, EMIT_EVENTS))
    } else {
        Box::new(HumanReporter::new(REPORT_INTERVAL))
    }
}

struct ClientResult {
    result: Result<Parts, OpaqueError>,
    req_start: Instant,
    phase: Phase,
    iteration: usize,
    index: usize,
}

async fn report_worker(
    guard: ShutdownGuard,
    mut reporter: Box<dyn Reporter>,
    mut result_rx: Receiver<ClientResult>,
) {
    let start = Instant::now();

    loop {
        let Some(ClientResult {
            result,
            req_start,
            phase,
            iteration,
            index,
        }) = recv_next_client_result(&guard, &mut result_rx).await
        else {
            return;
        };

        let outcome = compute_outcome_for_client_result(result);

        let ev = RequestResultEvent {
            ts: std::time::SystemTime::now(),
            elapsed: start.elapsed(),
            phase,
            iteration,
            index,
            latency: req_start.elapsed(),
            outcome,
        };

        reporter.on_result(&ev);

        let now = start.elapsed();
        reporter.on_tick(now);
    }
}

async fn recv_next_client_result(
    guard: &ShutdownGuard,
    result_rx: &mut mpsc::Receiver<ClientResult>,
) -> Option<ClientResult> {
    tokio::select! {
        _ = guard.cancelled() => {
            tracing::debug!("exit report worker: guard shutdown");
            None
        }

        maybe_result = result_rx.recv() => {
            let Some(result) = maybe_result else {
                tracing::debug!("exit report worker: result senders closed");
                return None;
            };

            Some(result)
        }
    }
}

fn compute_outcome_for_client_result(result: Result<Parts, OpaqueError>) -> RequestOutcome {
    match result {
        Ok(resp) => {
            let status = resp.status.as_u16();
            if (200..500).contains(&status) {
                RequestOutcome {
                    ok: true,
                    status: Some(status),
                    failure: None,
                }
            } else {
                RequestOutcome {
                    ok: false,
                    status: Some(status),
                    failure: Some(FailureKind::HttpStatus),
                }
            }
        }
        Err(err) => {
            tracing::debug!("non-http error: {err}");
            RequestOutcome {
                ok: err
                    .source()
                    .and_then(|e| e.downcast_ref::<std::io::Error>())
                    .map(is_connection_error)
                    .unwrap_or_default(),
                status: None,
                failure: Some(FailureKind::Other),
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RunParameters {
    target_rps: u32,
    burst_size: u32,
    jitter: f64,
    request_count_per_iteration: usize,
    request_count_per_warmup: usize,
    concurrency: usize,
}

impl RunParameters {
    fn new(
        scenario: Option<Scenario>,
        config: Option<ClientConfig>,
        iter_window_seconds: f64,
        warmup_window_seconds: f64,
    ) -> Self {
        let merged_cfg = merge_server_cfg(scenario, config);

        let target_rps = merged_cfg.target_rps.unwrap_or(200).max(1);
        let burst_size = merged_cfg.burst_size.unwrap_or_default().max(1);
        let jitter = merged_cfg.jitter.unwrap_or_default().clamp(0.0, 1.0);

        let request_count_per_iteration =
            (iter_window_seconds * target_rps as f64).next_up() as usize;
        let request_count_per_warmup =
            (warmup_window_seconds * target_rps as f64).next_up() as usize;

        let concurrency = {
            let c = merged_cfg.concurrency.unwrap_or_default();
            if c == 0 {
                env::compute_concurrent_request_count()
            } else {
                c as usize
            }
        };

        Self {
            target_rps,
            burst_size,
            jitter,
            request_count_per_iteration,
            request_count_per_warmup,
            concurrency,
        }
    }
}

fn merge_server_cfg(scenario: Option<Scenario>, config: Option<ClientConfig>) -> ClientConfig {
    let scenario_cfg = scenario
        .map(|s| {
            tracing::info!("use scenario to define base config: {s:?}");
            s.client_config()
        })
        .unwrap_or_else(|| {
            tracing::info!("no scenario defined, use default as base config");
            Default::default()
        });

    let overwrite_cfg = config.unwrap_or_default();

    macro_rules! merge_config {
        ($scenario:ident, $overwrite:ident, {$($property:ident),+ $(,)?}) => {
            ClientConfig {
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
            target_rps,
            concurrency,
            jitter,
            burst_size,
        }
    )
}
