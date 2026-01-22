/// Server side behavior configuration.
/// This models processing cost and instability.
#[derive(Debug, Clone, clap::Args, Default)]
pub struct ServerConfig {
    /// Base processing time before responding.
    #[arg(long, value_name = "SECONDS")]
    pub base_latency: Option<f64>,

    /// Random delay added to base_latency.
    /// Models IO waits and backend variability.
    #[arg(long, value_name = "SECONDS")]
    pub jitter: Option<f64>,

    /// Probability of returning an error response.
    #[arg(long)]
    pub error_rate: Option<f32>,

    /// Probability of dropping the connection.
    #[arg(long)]
    pub drop_rate: Option<f32>,

    /// Probability of never responding within client timeout.
    #[arg(long)]
    pub timeout_rate: Option<f32>,
}
