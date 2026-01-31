use std::{path::PathBuf, str::FromStr, sync::Arc};

use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::{
        Request, Response, StatusCode, headers::HeaderMapExt,
        service::web::response::IntoResponse as _,
    },
};
use safechain_proxy_lib::storage::SyncCompactDataStorage;

use crate::{
    http::{
        MockReplayIndex,
        har::{self, HarEntry},
    },
    mock::{self, BoxRequestMocker, RequestMocker},
};

#[derive(Debug, Clone)]
/// Emulation source, used to generate requests/responses
/// used in emulation.
pub(super) enum Source {
    /// Generate malware requests synthetically
    Synthetic(BoxRequestMocker),
    /// Replay requests from the given intries
    ///
    /// (ignores original timings)
    Har {
        index: usize,
        entries: Arc<[HarEntry]>,
    },
}

impl Source {
    pub(super) async fn try_new(
        kind: SourceKind,
        data_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError> {
        match kind {
            SourceKind::VSCode => Ok(Self::Synthetic(
                mock::vscode::VSCodeMocker::new(data_storage).into_dyn(),
            )),
            SourceKind::PyPI => Ok(Self::Synthetic(
                mock::pypi::PyPIMocker::new(data_storage).into_dyn(),
            )),
            SourceKind::Har(path) => {
                let entries = har::load_har_entries(path).await?.into();
                Ok(Self::Har { index: 0, entries })
            }
        }
    }

    pub(super) async fn next_request(&mut self) -> Result<Option<Request>, OpaqueError> {
        match self {
            Source::Synthetic(mocker) => mocker
                .mock_request(mock::MockRequestParameters { malware_ratio: 1. })
                .await
                .map(Some),
            Source::Har { index, entries } => Ok(entries.get(*index).map(|entry| {
                let mut req = entry.request.clone_as_http_request();
                req.headers_mut().typed_insert(MockReplayIndex(*index));
                *index += 1;
                req
            })),
        }
    }

    pub(super) async fn next_response_for(
        &mut self,
        req: Request,
    ) -> Result<Response, OpaqueError> {
        match self {
            Source::Synthetic(_) => Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                "synthetic request was not blocked",
            )
                .into_response()),
            Source::Har { index: _, entries } => {
                let Some(MockReplayIndex(index)) = req.headers().typed_get() else {
                    return Err(OpaqueError::from_display(
                        "har response could not replay: mock replay index missing",
                    ));
                };

                entries
                    .get(index)
                    .and_then(|entry| entry.response.as_ref())
                    .map(|resp| resp.clone_as_http_response())
                    .with_context(|| format!("har response for index: {index})"))
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Kind of source to use for emulation
pub(super) enum SourceKind {
    // Synthetic data based on vscode
    VSCode,
    // Synthetic data based on pypi
    PyPI,
    // Replay requests + responses from HAR
    Har(PathBuf),
}

impl FromStr for SourceKind {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed_s = s.trim();
        if trimmed_s.eq_ignore_ascii_case("vscode") {
            Ok(Self::VSCode)
        } else if trimmed_s.eq_ignore_ascii_case("pypi") {
            Ok(Self::PyPI)
        } else {
            let path: PathBuf = trimmed_s
                .parse()
                .context("parse unknown kind as (har) fs path")?;
            if !path.exists() {
                return Err(OpaqueError::from_display(format!(
                    "(source kind) HAR file path does not exist: '{}'",
                    path.display()
                )));
            }
            Ok(Self::Har(path))
        }
    }
}
