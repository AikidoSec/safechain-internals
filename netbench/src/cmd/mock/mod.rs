use clap::Args;
use rama::{error::OpaqueError, telemetry::tracing};

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
}

pub async fn exec(args: MockCommand) -> Result<(), OpaqueError> {
    let _merged_cfg = merge_server_cfg(args);

    Ok(())
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
