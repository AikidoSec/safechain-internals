use std::{path::PathBuf, sync::Arc, time::Duration};

use rama::{
    Service as _,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::Response,
    net::address::SocketAddress,
    rt::Executor,
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
    #[arg(long, default_value_t = 2)]
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
    let client =
        self::client::http_cient(Executor::graceful(guard.clone()), args.target, args.proxy)
            .context("create HTTP(S) client")?;

    let merged_cfg = merge_server_cfg(args.scenario, args.config);

    let target_rps = merged_cfg.target_rps.unwrap_or(200).max(1);
    let burst_size = merged_cfg.burst_size.unwrap_or_default().max(1);
    let jitter = merged_cfg.jitter.unwrap_or_default().clamp(0.0, 1.0);

    let request_count_per_iteration = (args.duration * target_rps as f64).next_up() as usize;
    let request_count_per_warmup = (args.warmup * target_rps as f64).next_up() as usize;

    let concurrency = {
        let c = merged_cfg.concurrency.unwrap_or_default();
        if c == 0 {
            env::compute_concurrent_request_count()
        } else {
            c as usize
        }
    };

    tracing::info!(
        %target_rps,
        %burst_size,
        %jitter,
        %request_count_per_iteration,
        %request_count_per_warmup,
        %concurrency,
        "client config parameters ready",
    );

    let iterations = args.iterations.max(1);

    let mut req_gen = match args.replay {
        Some(har_fp) => RequestGenerator::new_replay_gen(RequestGeneratorReplayConfig {
            har: har_fp,
            iterations,
            target_rps,
            burst_size,
            jitter,
            emulate_timing: args.emulate_timing,
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
            products: args.products,
            malware_ratio: args.malware_ratio,
        })
        .await
        .context("create mock req generator")?,
    };

    const REPORT_INTERVAL: Duration = Duration::from_secs(1);

    let reporter: Box<dyn Reporter> = if args.json {
        const EMIT_EVENTS: bool = true;
        Box::new(JsonlReporter::new(REPORT_INTERVAL, EMIT_EVENTS))
    } else {
        Box::new(HumanReporter::new(REPORT_INTERVAL))
    };

    let (result_tx, result_rx) = mpsc::channel(concurrency * 8);
    guard.spawn_task_fn(|guard| report_worker(guard, reporter, result_rx));

    let mut cancelled = std::pin::pin!(guard.clone_weak().into_cancelled());

    let concurrency = Arc::new(Semaphore::new(concurrency));

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

        let client = client.clone();
        let concurrency = concurrency.clone();
        let result_tx = result_tx.clone();

        guard.spawn_task_fn(async move |guard| {
            let _guard = tokio::select! {
                _ = guard.cancelled() => {
                    tracing::error!("cancel wait for concurrency: guard shutdown");
                    return;
                }
                guard_result = concurrency.acquire() => {
                    guard_result.expect("to always be able to acquire a semaphore guard")
                }
            };

            let req_start = Instant::now();
            let result = client.serve(req).await;
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
        });
    }
}

struct ClientResult {
    result: Result<Response, OpaqueError>,
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
        let ClientResult {
            result,
            req_start,
            phase,
            iteration,
            index,
        } = tokio::select! {
            _ = guard.cancelled() => {
                tracing::debug!("exit report worker: guard shutdown");
                return;
            }

            maybe_result = result_rx.recv() => {
                let Some(result) = maybe_result else {
                    tracing::debug!("exit report worker: result senders closed");
                    return;
                };

                result
            }
        };

        let outcome = match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if (200..400).contains(&status) {
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
                    ok: false,
                    status: None,
                    failure: Some(FailureKind::Other),
                }
            }
        };

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
