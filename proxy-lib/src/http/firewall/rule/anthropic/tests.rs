use super::*;
use rama::utils::str::arcstr::ArcStr;

// --- path_carries_model: Anthropic POST endpoints whose body has `model` ---

#[test]
fn test_path_carries_model_messages() {
    assert!(path_carries_model("/v1/messages"));
}

#[test]
fn test_path_carries_model_count_tokens() {
    assert!(path_carries_model("/v1/messages/count_tokens"));
}

#[test]
fn test_path_carries_model_batches() {
    assert!(path_carries_model("/v1/messages/batches"));
}

#[test]
fn test_path_carries_model_legacy_complete() {
    assert!(path_carries_model("/v1/complete"));
}

// --- path_carries_model: paths we should ignore ---

#[test]
fn test_path_carries_model_rejects_models_listing() {
    assert!(!path_carries_model("/v1/models"));
}

#[test]
fn test_path_carries_model_rejects_root() {
    assert!(!path_carries_model("/"));
}

#[test]
fn test_path_carries_model_rejects_unknown_path() {
    assert!(!path_carries_model("/v1/messages/something-else"));
}

// --- parse_model_field: typical Anthropic Messages API request bodies ---

#[test]
fn test_parse_model_basic() {
    let body = br#"{"model":"claude-3-5-sonnet-20241022","messages":[]}"#;
    assert_eq!(
        parse_model_field(body),
        Some(ArcStr::from("claude-3-5-sonnet-20241022"))
    );
}

#[test]
fn test_parse_model_with_extra_fields() {
    let body = br#"{
        "model": "claude-opus-4-7",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "hi"}]
    }"#;
    assert_eq!(
        parse_model_field(body),
        Some(ArcStr::from("claude-opus-4-7"))
    );
}

#[test]
fn test_parse_model_trims_whitespace() {
    let body = br#"{"model":"  claude-haiku-4-5  ","messages":[]}"#;
    assert_eq!(
        parse_model_field(body),
        Some(ArcStr::from("claude-haiku-4-5"))
    );
}

// --- parse_model_field: malformed inputs ---

#[test]
fn test_parse_model_missing_field() {
    let body = br#"{"messages":[]}"#;
    assert!(parse_model_field(body).is_none());
}

#[test]
fn test_parse_model_empty_string() {
    let body = br#"{"model":""}"#;
    assert!(parse_model_field(body).is_none());
}

#[test]
fn test_parse_model_invalid_json() {
    let body = b"not even json";
    assert!(parse_model_field(body).is_none());
}

#[test]
fn test_parse_model_wrong_type() {
    let body = br#"{"model":42}"#;
    assert!(parse_model_field(body).is_none());
}
