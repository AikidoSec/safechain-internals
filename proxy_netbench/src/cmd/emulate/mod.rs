use std::{path::PathBuf, time::Duration};

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
mod export;
mod filters;
mod source;

use self::{
    client::Client,
    filters::{
        SourceFilter,
        domain::{DomainFilter, parse_domain_filter},
        path::{PathFilter, parse_path_filter},
        range::RangeFilter,
    },
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

    #[arg(long)]
    /// post-filtered request range
    ///
    /// examples:
    ///
    /// - '3'
    /// - '..3'
    /// - '..=3'
    /// - '1..2'
    /// - '1..=2'
    range: Option<RangeFilter>,

    #[arg(long, value_parser = parse_domain_filter)]
    /// domains to filter on (by default all domains are allowed)
    ///
    /// examples:
    ///
    /// - 'example.com'
    /// - 'foo.example.com'
    /// - '*.example.com'
    domains: Option<DomainFilter>,

    #[arg(long, value_parser = parse_path_filter)]
    /// paths to filter on (by default all paths are allowed)
    ///
    /// examples:
    ///
    /// - '/'
    /// - '/foo/*'
    /// - '/user/{name}/foo'
    paths: Option<PathFilter>,

    #[arg(long)]
    /// exports requests which succeeded to a unique file in the given dir (path)
    export: Option<PathBuf>,

    /// Preserve sensitive headers when exporting requests.
    ///
    /// WARNING this can contain sensitive information such as credentials and
    /// similar derived info.
    #[arg(long, default_value_t = false)]
    preserve: bool,

    /// artificial delay in between req executions
    #[arg(long, value_name = "SECONDS", default_value_t = 0.)]
    gap: f64,

    /// caps how long this command is allowed to run for (min 1 second)
    #[arg(long, value_name = "SECONDS", default_value_t = 30.)]
    timeout: f64,
    // TODO:
    // - write diagnostics docs
    // - apply last feedback aikibot
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

    let (source, source_filter) = run_future_unless_cancelled(&guard, "create source", {
        let data_storage_clone = data_storage.clone();
        async move {
            let source = Source::try_new(args.source, data_storage_clone).await?;
            match source {
                har_src @ Source::Har { .. } => Ok((
                    har_src,
                    SourceFilter::new_har_filter(args.range, args.domains, args.paths),
                )),
                synthetic_src @ Source::Synthetic(_) => Ok((
                    synthetic_src,
                    SourceFilter::new_synthetic_filter(args.range, args.domains, args.paths),
                )),
            }
        }
    })
    .await?;

    let client = run_future_unless_cancelled(
        &guard,
        "create mock client",
        self::client::new_client(guard.clone(), data_storage, source.clone()),
    )
    .await?;

    let maybe_exporter = run_future_unless_cancelled(
        &guard,
        "maybe create (req) exporter",
        maybe_create_exporter(args.export, args.preserve),
    )
    .await?;

    tokio::time::timeout(
        Duration::from_secs_f64(args.timeout.max(1.)),
        exec_emulate_loop(
            &guard,
            client.clone(),
            maybe_exporter,
            source,
            source_filter,
            args.curl,
            args.gap,
        ),
    )
    .await
    .context("exec timeout")??;

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
    maybe_exporter: Option<self::export::Exporter>,
    mut source: Source,
    mut source_filter: SourceFilter,
    curl: bool,
    gap_secs: f64,
) -> Result<(), OpaqueError> {
    loop {
        let Some(req) =
            run_future_unless_cancelled(guard, "get next request from src", source.next_request())
                .await?
        else {
            return Ok(());
        };

        if !source_filter.filter(&req) {
            return Ok(());
        }

        if gap_secs > 0. {
            tokio::time::sleep(Duration::from_secs_f64(gap_secs)).await;
        }

        let (maybe_artifact, req) = if let Some(exporter) = maybe_exporter.as_ref() {
            tracing::debug!("prepare export artifect for req ({})", req.uri());
            let (artifact, req) = exporter.prepare_export_artifact(req).await?;
            (Some(artifact), req)
        } else {
            (None, req)
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

        let resp = client.serve(req).await?;

        if let Some(artifact) = maybe_artifact
            && (100..400).contains(&resp.status().as_u16())
        {
            tracing::debug!("export req artifact for unexpected success");
            artifact.export().await.context("export req artifact")?;
        }
    }
}

async fn maybe_create_exporter(
    dir: Option<PathBuf>,
    preserve_sensitive_headers: bool,
) -> Result<Option<self::export::Exporter>, OpaqueError> {
    let Some(dir) = dir else {
        return Ok(None);
    };

    let exporter = self::export::Exporter::try_new(dir, preserve_sensitive_headers).await?;
    Ok(Some(exporter))
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
