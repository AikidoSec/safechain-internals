use std::path::Path;

use rama::{error::BoxError, telemetry::tracing, utils::str::arcstr::ArcStr};

use crate::storage::app_path;

/// Permission group token used to authenticate with the Aikido endpoint protection API.
#[derive(Debug, Clone)]
pub struct PermissionToken(ArcStr);

impl PermissionToken {
    pub fn try_parse(raw: &str) -> Result<Self, BoxError> {
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err("token is empty".into());
        }

        if !trimmed.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return Err("token contains non-printable or non-ASCII characters".into());
        }

        Ok(Self(ArcStr::from(trimmed)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn load_token() -> Option<PermissionToken> {
    let token = load_token_inner();
    if token.is_some() {
        tracing::info!("Aikido authentication token loaded");
    } else {
        tracing::info!(
            "no Aikido authentication token found; endpoint protection features disabled"
        );
    }
    token
}

fn load_token_inner() -> Option<PermissionToken> {
    let system_path = app_path::resolve(".token");
    if let Some(token) = try_load_from_path(&system_path) {
        return Some(token);
    }

    // Fallback: Try relative path in CWD
    try_load_from_path(Path::new(".token"))
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
