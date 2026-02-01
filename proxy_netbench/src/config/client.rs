/// Client side load generation configuration.
/// This models how requests are produced over time.
#[derive(Debug, Clone, clap::Args, Default)]
pub struct ClientConfig {
    /// Target average requests per second.
    #[arg(long, value_name = "SECONDS")]
    pub target_rps: Option<u32>,

    /// Maximum number of in flight requests.
    #[arg(long, value_name = "N")]
    pub concurrency: Option<u32>,

    /// Random scheduling delay added per request.
    /// Models uneven producers and event loop jitter.
    #[arg(long, value_name = "SECONDS")]
    pub jitter: Option<f64>,

    /// Number of requests sent together before a pause.
    #[arg(long, value_name = "#REQUESTS")]
    pub burst_size: Option<u32>,
}
