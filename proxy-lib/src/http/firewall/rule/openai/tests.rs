use super::*;
use rama::utils::str::arcstr::ArcStr;

// --- path_carries_model: OpenAI JSON endpoints whose body has `model` ---

#[test]
fn test_path_carries_model_responses() {
    assert!(path_carries_model("/v1/responses"));
}

#[test]
fn test_path_carries_model_responses_compact() {
    assert!(path_carries_model("/v1/responses/compact"));
}

#[test]
fn test_path_carries_model_chat_completions() {
    assert!(path_carries_model("/v1/chat/completions"));
}

#[test]
fn test_path_carries_model_embeddings() {
    assert!(path_carries_model("/v1/embeddings"));
}

#[test]
fn test_path_carries_model_moderations() {
    assert!(path_carries_model("/v1/moderations"));
}

#[test]
fn test_path_carries_model_codex_responses() {
    assert!(path_carries_model("/backend-api/codex/responses"));
}

// --- path_carries_model: paths we should ignore ---

#[test]
fn test_path_carries_model_rejects_models_listing() {
    assert!(!path_carries_model("/v1/models"));
}

#[test]
fn test_path_carries_model_rejects_codex_root() {
    assert!(!path_carries_model("/backend-api/codex"));
}

#[test]
fn test_path_carries_model_rejects_codex_subpath() {
    assert!(!path_carries_model("/backend-api/codex/responses/extra"));
}

#[test]
fn test_path_carries_model_rejects_files() {
    assert!(!path_carries_model("/v1/files"));
}

#[test]
fn test_path_carries_model_rejects_audio_transcriptions() {
    assert!(!path_carries_model("/v1/audio/transcriptions"));
}

#[test]
fn test_path_carries_model_rejects_other_chatgpt_backend_paths() {
    assert!(!path_carries_model("/backend-api/models"));
}

// --- parse_model_field: typical OpenAI request bodies ---

#[test]
fn test_parse_model_basic() {
    let body = br#"{"model":"gpt-4o","input":"hello"}"#;
    assert_eq!(parse_model_field(body), Some(ArcStr::from("gpt-4o")));
}

#[test]
fn test_parse_model_with_extra_fields() {
    let body = br#"{
        "model": "o4-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "temperature": 1
    }"#;
    assert_eq!(parse_model_field(body), Some(ArcStr::from("o4-mini")));
}

#[test]
fn test_parse_model_trims_whitespace() {
    let body = br#"{"model":"  text-embedding-3-large  ","input":"hello"}"#;
    assert_eq!(
        parse_model_field(body),
        Some(ArcStr::from("text-embedding-3-large"))
    );
}

// --- parse_model_field: malformed inputs ---

#[test]
fn test_parse_model_missing_field() {
    let body = br#"{"input":"hello"}"#;
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
