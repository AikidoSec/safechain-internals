pub const fn project_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

pub const fn server_identifier() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"))
}

pub fn compute_concurrent_request_count() -> usize {
    std::env::var("MAX_CONCURRENT_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            cpus * 64
        })
}
