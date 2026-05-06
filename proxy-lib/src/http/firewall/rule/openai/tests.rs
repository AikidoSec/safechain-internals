use super::*;
use rama::utils::str::arcstr::ArcStr;

// --- parse_model_field: typical Codex Ingress prompt bodies ---

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
    let body = br#"{"model":"  gpt-5.4  ","input":"hello"}"#;
    assert_eq!(parse_model_field(body), Some(ArcStr::from("gpt-5.4")));
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
