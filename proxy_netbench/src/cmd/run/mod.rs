use std::path::PathBuf;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    telemetry::tracing,
};

use clap::Args;

use safechain_proxy_lib::storage;

use crate::config::{ClientConfig, ProductValues, Scenario, parse_product_values, rand_requests};

// TODO: also create client here that we will use... which includes har recording..

#[derive(Debug, Clone, Args)]
/// run benhmarker
pub struct RunCommand {
    #[clap(flatten)]
    config: Option<ClientConfig>,

    /// Iteration duration
    #[arg(long, value_name = "SECONDS", default_value_t = 10.)]
    duration: f64,

    /// Warmup duration
    #[arg(long, value_name = "SECONDS", default_value_t = 5.)]
    warmup: f64,

    /// Amount of times we run through the samples
    #[arg(long, default_value_t = 4)]
    iterations: usize,

    #[arg(long, value_parser = parse_product_values)]
    /// Scenario to run,
    /// manually defined parameters overwrite scenario parameters.
    products: Option<ProductValues>,

    #[arg(long)]
    /// Scenario to run,
    /// manually defined parameters overwrite scenario parameters.
    scenario: Option<Scenario>,
}

pub async fn exec(data: PathBuf, args: RunCommand) -> Result<(), OpaqueError> {
    tokio::fs::create_dir_all(&data)
        .await
        .with_context(|| format!("create data directory at path '{}'", data.display()))?;
    let data_storage =
        storage::SyncCompactDataStorage::try_new(data.clone()).with_context(|| {
            format!(
                "create compact data storage using dir at path '{}'",
                data.display()
            )
        })?;
    tracing::info!(path = ?data, "data directory ready to be used");

    let merged_cfg = merge_server_cfg(args.scenario, args.config);

    let target_rps = merged_cfg.target_rps.unwrap_or(1000);
    let request_count_per_iteration = (args.duration * target_rps as f64).next_up() as usize;
    let request_count_per_warmup = (args.warmup * target_rps as f64).next_up() as usize;

    let iterations = args.iterations.max(1);
    let mut requests_per_iteration = Vec::with_capacity(iterations);
    for i in 0..iterations {
        tracing::info!(
            "generate #{request_count_per_iteration} random requests for iteration {i} / {iterations}"
        );
        let requests = rand_requests(
            &data_storage,
            request_count_per_iteration,
            args.products.clone(),
        )
        .await?;
        requests_per_iteration.push(requests);
    }

    tracing::info!("generate #{request_count_per_warmup} random requests for warmup");
    let _requests = rand_requests(
        &data_storage,
        request_count_per_warmup,
        args.products.clone(),
    )
    .await?;

    Ok(())
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
