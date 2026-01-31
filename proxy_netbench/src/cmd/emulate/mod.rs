use std::{path::PathBuf, str::FromStr};

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, body::util::BodyExt, convert::curl},
    telemetry::tracing,
};

use clap::Args;
use safechain_proxy_lib::{firewall::version::PackageVersion, storage};

use crate::mock::{self, MockRequestParameters, RequestMocker};

mod client;

#[derive(Debug, Clone)]
/// Product to emulate
enum Product {
    VSCode,
    PyPI,
}

#[derive(Debug, Clone, Args)]
/// emulate a request that is to be blocked
pub struct EmulateCommand {
    /// product to emulate (e.g. vscode, pypi, ...)
    #[arg(required = true)]
    product: Product,

    /// instead of emulating return a curl request
    #[arg(long, default_value_t = false)]
    curl: bool,
}

pub async fn exec(
    data: PathBuf,
    guard: ShutdownGuard,
    args: EmulateCommand,
) -> Result<(), OpaqueError> {
    let req = tokio::select! {
        _ = guard.cancelled() => {
            return Err(OpaqueError::from_display("exit cmd while generating mock req"));
        }

        result = create_mock_req(data.clone(), args.product) => {
            result?
        }
    };

    if args.curl {
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
        return Ok(());
    }

    tracing::info!("emulate request: {req:?}");
    emulate_req(data, guard, req).await
}

async fn emulate_req(data: PathBuf, guard: ShutdownGuard, req: Request) -> Result<(), OpaqueError> {
    let client = self::client::new_client(guard, data).await?;

    let resp = client.serve(req).await?;

    if resp.status().is_success() {
        return Err(OpaqueError::from_display(format!(
            "unexpected response: {resp:?}"
        )));
    }

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

async fn create_mock_req(data: PathBuf, product: Product) -> Result<Request, OpaqueError> {
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

    let mock_req_params = MockRequestParameters { malware_ratio: 1.0 };

    match product {
        Product::VSCode => mock::vscode::VSCodeMocker::new(data_storage)
            .mock_request(mock_req_params)
            .await
            .context("mock vscode request"),
        Product::PyPI => mock::pypi::PyPIMocker::new(data_storage)
            .mock_request(mock_req_params)
            .await
            .context("mock pypi request"),
    }
}

impl FromStr for Product {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed_s = s.trim();
        if trimmed_s.eq_ignore_ascii_case("vscode") {
            Ok(Self::VSCode)
        } else if trimmed_s.eq_ignore_ascii_case("pypi") {
            Ok(Self::PyPI)
        } else {
            Err(OpaqueError::from_display(format!("unknown variant '{s}'")))
        }
    }
}
