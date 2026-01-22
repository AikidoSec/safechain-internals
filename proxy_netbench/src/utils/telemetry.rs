use std::io::IsTerminal as _;

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::{
        self,
        metadata::LevelFilter,
        subscriber::{EnvFilter, fmt::writer::BoxMakeWriter},
    },
};

use crate::Args;

/// Configures structured logging with runtime control via `RUST_LOG` environment variable.
///
/// Defaults to INFO level to balance visibility with performance.
/// Use `RUST_LOG=debug` or `RUST_LOG=trace` for troubleshooting.
pub fn init_tracing(args: &Args) -> Result<(), BoxError> {
    let directive = if args.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    }
    .into();

    let make_writer = match args.output.as_deref() {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .context("open log file")?;

            BoxMakeWriter::new(file)
        }
        None => BoxMakeWriter::new(std::io::stderr),
    };

    let subscriber = tracing::subscriber::fmt()
        .with_ansi(args.output.is_none() && std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(directive)
                .from_env_lossy(),
        )
        .with_writer(make_writer);

    if args.pretty {
        subscriber.pretty().try_init()?;
    } else {
        subscriber.try_init()?;
    }

    tracing::info!("Tracing is set up");
    Ok(())
}
