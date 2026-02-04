use std::path::PathBuf;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::{Body, Request, body::util::BodyExt, layer::har},
    telemetry::tracing,
};
use safechain_proxy_lib::http::{remove_sensitive_req_headers, try_req_to_filename};

/// Exporter of requests as HAR files.
///
/// Useful for creating test cases and diagnostics.
pub(super) struct Exporter {
    dir: PathBuf,
    preserve_sensitive_headers: bool,
}

#[derive(Debug)]
pub(super) struct ExportArtifact {
    req: har::spec::Request,
    path: PathBuf,
}

impl Exporter {
    pub(super) async fn try_new(
        dir: PathBuf,
        preserve_sensitive_headers: bool,
    ) -> Result<Self, OpaqueError> {
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create export directory at path '{}'", dir.display()))?;
        tracing::info!(path = ?dir, "exporter directory ready to be used");

        Ok(Self {
            dir,
            preserve_sensitive_headers,
        })
    }

    pub(super) async fn prepare_export_artifact(
        &self,
        req: Request,
    ) -> Result<(ExportArtifact, Request), OpaqueError> {
        let (parts, body) = req.into_parts();
        let bytes = body
            .collect()
            .await
            .context("collect req body as bytes")?
            .to_bytes();

        let har_req = if self.preserve_sensitive_headers {
            har::spec::Request::from_http_request_parts(&parts, &bytes)
                .context("create HAR request from http request parts")?
        } else {
            let mut mod_parts = parts.clone();
            remove_sensitive_req_headers(&mut mod_parts.headers);
            har::spec::Request::from_http_request_parts(&mod_parts, &bytes)
                .context("create HAR request from (filtered) http request parts")?
        };

        let req = Request::from_parts(parts, Body::from(bytes));

        let basename = try_req_to_filename(&req).context("req to filename str")?;
        let filename = self.dir.join(basename.as_str());

        Ok((
            ExportArtifact {
                req: har_req,
                path: filename,
            },
            req,
        ))
    }
}

impl ExportArtifact {
    pub(super) async fn export(&self) -> Result<(), OpaqueError> {
        let v = serde_json::to_vec(&self.req).context("JSON serialize export req (HAR)")?;
        tokio::fs::write(&self.path, &v)
            .await
            .context("write (JSON) HAR export req")
    }
}
