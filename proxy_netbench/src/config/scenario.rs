use safechain_proxy_lib::utils;

use super::{ClientConfig, ServerConfig};

/// High level benchmark scenarios.
/// Each scenario is a preset of client and server behavior.
#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum Scenario {
    /// Ideal conditions.
    /// Used to measure pure overhead and regressions.
    #[default]
    Baseline,

    /// Variable latency on both client and server.
    /// Used to observe queuing and tail latency.
    LatencyJitter,

    /// Unstable upstream behavior.
    /// Used to test error handling and resilience.
    FlakyUpstream,
}

impl Scenario {
    /// Construct the concrete client configuration
    /// associated with this scenario.
    pub fn client_config(self) -> ClientConfig {
        match self {
            Scenario::Baseline => {
                // Smooth request generation with no randomness.
                let concurrency = utils::env::compute_concurrent_request_count() as u32;
                ClientConfig {
                    target_rps: Some(concurrency),
                    concurrency: Some(concurrency),
                    jitter: None,
                    burst_size: Some(1),
                }
            }

            Scenario::LatencyJitter => {
                // Requests are sent at an uneven pace.
                // This introduces burstiness and queue formation.
                ClientConfig {
                    target_rps: Some(500),
                    concurrency: Some(100),
                    jitter: Some(0.005),
                    burst_size: Some(2),
                }
            }

            Scenario::FlakyUpstream => {
                // Client side jitter is higher to simulate unstable producers.
                ClientConfig {
                    target_rps: Some(250),
                    concurrency: Some(50),
                    jitter: Some(0.01),
                    burst_size: Some(2),
                }
            }
        }
    }

    /// Construct the concrete server configuration
    /// associated with this scenario.
    pub fn server_config(self) -> ServerConfig {
        match self {
            Scenario::Baseline => {
                // Fast and fully reliable server.
                ServerConfig {
                    base_latency: Some(0.02),
                    jitter: None,
                    error_rate: None,
                    drop_rate: None,
                    timeout_rate: None,
                }
            }

            Scenario::LatencyJitter => {
                // Server processing time varies per request.
                // This is the main source of tail latency.
                ServerConfig {
                    base_latency: Some(0.05),
                    jitter: Some(1.),
                    error_rate: None,
                    drop_rate: None,
                    timeout_rate: None,
                }
            }

            Scenario::FlakyUpstream => {
                // Server occasionally errors, drops, or stalls.
                // This exercises retry paths and cleanup logic.
                ServerConfig {
                    base_latency: Some(0.1),
                    jitter: Some(2.),
                    error_rate: Some(0.05),
                    drop_rate: Some(0.05),
                    timeout_rate: Some(0.05),
                }
            }
        }
    }
}
