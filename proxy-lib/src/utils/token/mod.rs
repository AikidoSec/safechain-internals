use std::path::Path;

use rama::{error::BoxError, telemetry::tracing, utils::str::arcstr::ArcStr};

use crate::storage::app_path;

const TOKEN_PREFIX: &str = "mdm_";

/// Permission group token used to authenticate with the Aikido endpoint protection API.
///
/// Tokens are issued per permission group and follow the format `mdm_<secret>`.
#[derive(Debug, Clone)]
pub struct PermissionToken(ArcStr);

impl PermissionToken {
    pub fn try_parse(raw: &str) -> Result<Self, BoxError> {
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err("token is empty".into());
        }

        if !trimmed.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("token contains non-printable, whitespace, or non-ASCII characters".into());
        }

        if !trimmed.starts_with(TOKEN_PREFIX) {
            return Err(format!(
                "token must start with '{TOKEN_PREFIX}' prefix"
            )
            .into());
        }

        if trimmed.len() <= TOKEN_PREFIX.len() {
            return Err("token is missing the secret part after the prefix".into());
        }

        Ok(Self(ArcStr::from(trimmed)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn load_token() -> Option<PermissionToken> {
    let system_path = app_path::resolve(".token");
    let token = try_load_from_path(&system_path).or_else(|| {
        // Fallback: try relative path in CWD
        try_load_from_path(Path::new(".token"))
    });

    if token.is_some() {
        tracing::info!("Aikido authentication token loaded");
    } else {
        tracing::info!(
            "No Aikido authentication token found; Some endpoint protection features will be disabled"
        );
    }

    token
}

fn try_load_from_path(path: &Path) -> Option<PermissionToken> {
    if !path.exists() {
        return None;
    }

    // Check file size before reading to prevent DoS
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "failed to read token file metadata");
            return None;
        }
    };

    const MAX_TOKEN_SIZE: u64 = 1024; // 1KB max
    if metadata.len() > MAX_TOKEN_SIZE {
        tracing::warn!(
            path = %path.display(),
            size = metadata.len(),
            max = MAX_TOKEN_SIZE,
            "token file exceeds maximum size; ignoring",
        );
        return None;
    }

    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "failed to read token file");
            return None;
        }
    };

    match PermissionToken::try_parse(&raw) {
        Ok(token) => Some(token),
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "invalid token; ignoring");
            None
        }
    }
}

#[cfg(test)]
mod tests;
