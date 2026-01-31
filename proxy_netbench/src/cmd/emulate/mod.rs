use std::path::PathBuf;

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{body::util::BodyExt, convert::curl},
    telemetry::tracing,
};

use clap::Args;
use safechain_proxy_lib::{
    firewall::version::PackageVersion,
    storage::{self, SyncCompactDataStorage},
};

mod client;
mod source;

use self::{
    client::Client,
    source::{Source, SourceKind},
};

#[derive(Debug, Clone, Args)]
/// emulate a request that is to be blocked
pub struct EmulateCommand {
    /// emulation source (synthetic id such as vscode, pypi, or else a HAR file path to replay)
    #[arg(required = true)]
    source: SourceKind,

    /// instead of emulating return a curl request
    #[arg(long, default_value_t = false)]
    curl: bool,
}

pub async fn exec(
    data: PathBuf,
    guard: ShutdownGuard,
    args: EmulateCommand,
) -> Result<(), OpaqueError> {
    let data_storage = run_future_unless_cancelled(
        &guard,
        "create data storage",
        create_data_storage(data.clone()),
    )
    .await?;

    let source = run_future_unless_cancelled(
        &guard,
        "create source",
        Source::try_new(args.source, data_storage.clone()),
    )
    .await?;

    let client = run_future_unless_cancelled(
        &guard,
        "create mock client",
        self::client::new_client(guard.clone(), data_storage, source.clone()),
    )
    .await?;

    exec_emulate_loop(&guard, client.clone(), source, args.curl).await?;

    client.wait_for_blocked_events().await?;
    for blocked_event in client.blocked_events() {
        println!(
            "[{}] blocked event: product={}; identifier={}; version={}",
            blocked_event.ts_ms,
            blocked_event.artifact.product,
            blocked_event.artifact.identifier,
            blocked_event
                .artifact
                .version
                .clone()
                .unwrap_or_else(|| PackageVersion::None),
        );
    }

    Ok(())
}

async fn exec_emulate_loop(
    guard: &ShutdownGuard,
    client: Client,
    mut source: Source,
    curl: bool,
) -> Result<(), OpaqueError> {
    loop {
        let Some(req) =
            run_future_unless_cancelled(guard, "get next request from src", source.next_request())
                .await?
        else {
            return Ok(());
        };

        if curl {
            let (parts, body) = req.into_parts();
            let bytes = body
                .collect()
                .await
                .context("collect (mock) req payload")?
                .to_bytes();

            println!(
                "{}",
                curl::cmd_string_for_request_parts_and_payload(&parts, &bytes)
            );
            continue;
        }

        let _resp = client.serve(req).await?;
    }
}

async fn create_data_storage(data: PathBuf) -> Result<SyncCompactDataStorage, OpaqueError> {
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

    Ok(data_storage)
}

async fn run_future_unless_cancelled<F, T>(
    guard: &ShutdownGuard,
    desc: &'static str,
    fut: F,
) -> Result<T, OpaqueError>
where
    F: Future<Output = Result<T, OpaqueError>>,
{
    tokio::select! {
        _ = guard.cancelled() => {
            Err(OpaqueError::from_display(format!("exit cmd while: {desc}")))
        }

        result = fut => {
            result
        }
    }
}
