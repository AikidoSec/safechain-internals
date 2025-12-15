use std::io::IsTerminal as _;

use rama::telemetry::tracing::{
    self,
    metadata::LevelFilter,
    subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _},
};

use crate::Args;

/// Configures structured logging with runtime control via `RUST_LOG` environment variable.
///
/// Defaults to INFO level to balance visibility with performance.
/// Use `RUST_LOG=debug` or `RUST_LOG=trace` for troubleshooting.
pub fn init_tracing(args: &Args) {
    let directive = if args.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    }
    .into();

    // TODO: support FS Logging

    if args.pretty {
        tracing::subscriber::fmt()
            .pretty()
            .with_ansi(std::io::stderr().is_terminal())
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(directive)
                    .from_env_lossy(),
            )
            .init();
    } else {
        tracing::subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(directive)
                    .from_env_lossy(),
            )
            .init();
    }

    tracing::info!("Tracing is set up");
}

// NOTES for development team:
//
// Rama also supports OpenTelemetry:
//   - For tracing (with spans)
//   - As well as metrics
//
// Reach out to Glen (rama) if you need help with setting this up.
//
// Relevant docs:
//
// - setup: <https://ramaproxy.org/docs/rama/telemetry/opentelemetry/index.html>
// - http metrics layer: <https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html>
// - transport (e.g. tcp) metrics layer: <https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/index.html>
//
