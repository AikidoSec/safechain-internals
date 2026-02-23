use std::path::Path;

use rama::{
    error::{BoxError, ErrorContext},
    telemetry::tracing,
};

pub fn load_token() -> Result<Option<String>, BoxError> {
    // Try 1: Absolute system path
    #[cfg(target_os = "macos")]
    let system_path = "/Library/Application Support/AikidoSecurity/SafeChainUltimate/.token";

    #[cfg(target_os = "windows")]
    let system_path = r"C:\ProgramData\AikidoSecurity\SafeChainUltimate\.token";

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let system_path = "";

    if system_path.is_empty() {
        return try_load_from_path(".token");
    }

    if let Some(token) = try_load_from_path(system_path)? {
        return Ok(Some(token));
    }

    // Fallback: Try relative path
    try_load_from_path(".token")
}

fn try_load_from_path(path: &str) -> Result<Option<String>, BoxError> {
    let token_path = Path::new(path);

    if !token_path.exists() {
        return Ok(None);
    }

    // Check file size before reading to prevent DoS
    let metadata = std::fs::metadata(token_path)
        .context("failed to read token file metadata")
        .with_context_debug_field("path", || path.to_string())?;

    const MAX_TOKEN_SIZE: u64 = 1024; // 1KB max
    if metadata.len() > MAX_TOKEN_SIZE {
        tracing::warn!(
            path = path,
            size = metadata.len(),
            "token file exceeds maximum size ({}  bytes); ignoring",
            MAX_TOKEN_SIZE
        );
        return Ok(None);
    }

    let token = std::fs::read_to_string(token_path)
        .context("failed to read .token file")
        .with_context_debug_field("path", || path.to_string())?;

    let token = token.trim().to_string();

    if token.is_empty() {
        return Ok(None);
    }

    // Ignore invalid token formats instead of failing startup.
    if let Err(err) = validate_token(&token) {
        tracing::warn!(
            path = path,
            error = %err,
            "invalid token format; ignoring"
        );
        return Ok(None);
    }

    Ok(Some(token))
}

fn validate_token(token: &str) -> Result<(), BoxError> {
    const MIN_TOKEN_LENGTH: usize = 16;
    if token.len() < MIN_TOKEN_LENGTH {
        return Err(format!(
            "token too short (minimum {} characters required)",
            MIN_TOKEN_LENGTH
        )
        .into());
    }

    if token.chars().any(|c| c.is_control()) {
        return Err("token contains invalid control characters".into());
    }

    if !token.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err("token contains non-ASCII or control characters".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_token_success() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join(".token");

        fs::write(&token_path, "valid_token_abc123xyz").unwrap();

        let result = try_load_from_path(token_path.to_str().unwrap()).unwrap();
        assert_eq!(result, Some("valid_token_abc123xyz".to_string()));
    }

    #[test]
    fn test_load_token_not_exists() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join(".token");

        let result = try_load_from_path(token_path.to_str().unwrap()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_token_too_short() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join(".token");

        fs::write(&token_path, "short").unwrap();

        let result = try_load_from_path(token_path.to_str().unwrap()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_token_with_control_chars() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join(".token");

        fs::write(&token_path, "token_with_newline\n_injection_12345").unwrap();

        let result = try_load_from_path(token_path.to_str().unwrap()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_token_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join(".token");

        // Create a token larger than 1KB
        let large_token = "a".repeat(2 * 1024);
        fs::write(&token_path, large_token).unwrap();

        let result = try_load_from_path(token_path.to_str().unwrap()).unwrap();
        assert!(result.is_none());
    }
}
