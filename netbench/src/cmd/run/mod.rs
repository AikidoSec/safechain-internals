use clap::Args;
use rama::{error::OpaqueError, telemetry::tracing};

use crate::config::{ClientConfig, ProductValues, Scenario, parse_product_values, rand_requests};

#[derive(Debug, Clone, Args)]
/// run benhmarker
pub struct RunCommand {
    #[clap(flatten)]
    config: Option<ClientConfig>,

    /// Duration of the samples
    #[arg(long, value_name = "SECONDS", default_value_t = 10.)]
    duration: f64,

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

pub async fn exec(args: RunCommand) -> Result<(), OpaqueError> {
    let merged_cfg = merge_server_cfg(args.scenario, args.config);

    let target_rps = merged_cfg.target_rps.unwrap_or(1000);
    let total_request_count = (args.duration * target_rps as f64).next_up() as usize;

    let iterations = args.iterations.max(1);
    let mut requests_per_iteration = Vec::with_capacity(iterations);
    for i in 0..iterations {
        tracing::info!(
            "generate #{total_request_count} random requests for iteration {i} / {iterations}"
        );
        let requests = rand_requests(total_request_count, args.products.clone()).await?;
        requests_per_iteration.push(requests);
    }

    println!("{requests_per_iteration:?}");

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
