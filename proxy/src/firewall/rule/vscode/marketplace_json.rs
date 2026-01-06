use std::borrow::Cow;

use rama::bytes::Bytes;
use rama::telemetry::tracing;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::RuleVSCode;

impl RuleVSCode {
    pub(super) fn rewrite_marketplace_json_response_body(
        &self,
        body_bytes: &[u8],
    ) -> Option<Bytes> {
        rewrite_marketplace_json_response_body_with_predicate(body_bytes, |extension_id| {
            self.is_extension_id_malware(extension_id)
        })
    }
}

/// Attempts to parse a VS Code Marketplace JSON response body and rewrites it in-place
/// to mark extensions as malware when `is_malware(extension_id)` returns true.
///
/// This is intentionally tolerant:
/// - It can handle the common `extensionquery` response shape (`results -> [ { extensions: [...] } ]`).
/// - It also scans nested JSON objects and only rewrites objects that *look like* extension entries.
///
/// # Returns
/// - `Some(Bytes)` with the rewritten JSON if any changes were made.
/// - `None` if parsing failed or no rewrite was needed.
fn rewrite_marketplace_json_response_body_with_predicate(
    body_bytes: &[u8],
    mut is_malware: impl FnMut(&str) -> bool,
) -> Option<Bytes> {
    // If the payload doesn't contain the minimum set of markers required
    // for an extension-like object we would rewrite, skip parsing entirely.
    let body_str = std::str::from_utf8(body_bytes).ok()?;

    // We only rewrite objects that have a display name, plus enough metadata to build
    // an extension id (publisher + name). If these markers are absent, no rewrite is possible.
    if !body_str.contains("\"displayName\"") {
        return None;
    }

    if !(body_str.contains("\"publisherName\"") || body_str.contains("\"publisher\"")) {
        return None;
    }

    if !(body_str.contains("\"extensionName\"") || body_str.contains("\"name\"")) {
        return None;
    }

    let mut value: Value = match serde_json::from_slice(body_bytes) {
        Ok(val) => val,
        Err(err) => {
            tracing::trace!(error = %err, "VSCode response: failed to parse JSON; passthrough");
            return None;
        }
    };

    let modified = mark_any_extensions_if_malware(&mut value, &mut is_malware);
    if !modified {
        return None;
    }

    match serde_json::to_vec(&value) {
        Ok(modified_bytes) => Some(Bytes::from(modified_bytes)),
        Err(err) => {
            tracing::debug!(
                error = %err,
                "Failed to serialize modified VSCode response; passing original through"
            );
            None
        }
    }
}

/// Recursively walks a JSON value and rewrites any objects that *look like* VS Code
/// Marketplace extension entries. This is deliberately schema-tolerant.
fn mark_any_extensions_if_malware(
    value: &mut Value,
    is_malware: &mut impl FnMut(&str) -> bool,
) -> bool {
    mark_any_extensions_if_malware_with_depth(value, is_malware, 0)
}

pub(super) const MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH: usize = 32;

fn mark_any_extensions_if_malware_with_depth(
    value: &mut Value,
    is_malware: &mut impl FnMut(&str) -> bool,
    depth: usize,
) -> bool {
    if depth >= MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH {
        tracing::trace!(
            max_depth = MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH,
            "VSCode response JSON traversal depth limit reached; stopping traversal"
        );
        return false;
    }

    match value {
        Value::Array(values) => values.iter_mut().fold(false, |acc, child| {
            mark_any_extensions_if_malware_with_depth(child, is_malware, depth + 1) || acc
        }),
        Value::Object(_) => {
            let keys: Vec<String> = value
                .as_object()
                .expect("Value::Object implies as_object is Some")
                .keys()
                .cloned()
                .collect();

            let mut modified = false;
            let obj = value
                .as_object_mut()
                .expect("Value::Object implies as_object_mut is Some");

            for key in keys {
                if let Some(child) = obj.get_mut(&key) {
                    modified |=
                        mark_any_extensions_if_malware_with_depth(child, is_malware, depth + 1);
                }
            }

            modified |= mark_extension_object_if_malware(value, is_malware);
            modified
        }
        _ => false,
    }
}

/// If `value` is a JSON object that looks like a VS Code Marketplace extension entry,
/// rewrite it in-place when it matches the malware predicate.
///
/// - The object must contain enough fields to build an extension id (`publisher.name`).
/// - And it must also contain an "extension-ish" field (`displayName`).
///
/// Returns `true` if the object was rewritten.
fn mark_extension_object_if_malware(
    value: &mut Value,
    is_malware: &mut impl FnMut(&str) -> bool,
) -> bool {
    let Value::Object(obj) = value else {
        return false;
    };

    // Deserialize only the fields we care about (ignores unknown fields).
    let obj_clone = obj.clone();
    let extension_like: ExtensionLike = match serde_json::from_value(Value::Object(obj_clone)) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Require a display name to reduce accidental matches in unrelated JSON objects.
    if extension_like.display_name.is_none() {
        return false;
    }

    let Some(extension_id) = extension_id(&extension_like) else {
        return false;
    };

    if !is_malware(&extension_id) {
        return false;
    }

    tracing::info!(
        package = %extension_id,
        "marked malware VSCode extension as blocked in API response"
    );

    rewrite_extension_object(obj, &extension_like);
    true
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PublisherLike<'a> {
    #[serde(rename = "publisherName")]
    publisher_name: Option<Cow<'a, str>>,
    name: Option<Cow<'a, str>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ExtensionLike<'a> {
    publisher: Option<PublisherLike<'a>>,

    #[serde(rename = "publisherName")]
    publisher_name: Option<Cow<'a, str>>,

    #[serde(rename = "extensionName")]
    extension_name: Option<Cow<'a, str>>,

    name: Option<Cow<'a, str>>,

    #[serde(rename = "displayName")]
    display_name: Option<Cow<'a, str>>,
}

fn extension_id(ext: &ExtensionLike<'_>) -> Option<String> {
    let publisher = extract_publisher_name(ext)?;
    let name = extract_extension_name(ext)?;
    Some(format!("{publisher}.{name}"))
}

/// Extract and validate publisher name from extension metadata.
fn extract_publisher_name(ext: &ExtensionLike<'_>) -> Option<&str> {
    // Try nested publisher object first
    let from_nested = ext
        .publisher
        .as_ref()
        .and_then(|p| p.publisher_name.as_deref().or(p.name.as_deref()));
    
    // Fall back to flat publisher_name field
    let raw_publisher = from_nested.or(ext.publisher_name.as_deref())?;
    
    // Trim and validate non-empty
    let trimmed = raw_publisher.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Extract and validate extension name from extension metadata.
fn extract_extension_name(ext: &ExtensionLike<'_>) -> Option<&str> {
    let raw_name = ext
        .extension_name
        .as_deref()
        .or(ext.name.as_deref())?;
    
    // Trim and validate non-empty
    let trimmed = raw_name.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn rewrite_extension_object(obj: &mut Map<String, Value>, ext: &ExtensionLike<'_>) {
    let original_name = obj
        .get("displayName")
        .and_then(|v| v.as_str())
        .or(ext.extension_name.as_deref().or(ext.name.as_deref()))
        .unwrap_or("<unknown>");

    obj.insert(
        "displayName".to_string(),
        Value::String(format!("⛔ MALWARE: {original_name}")),
    );

    const BLOCK_MSG: &str = "This extension has been marked as malware by Aikido safe-chain. Installation will be blocked.";

    obj.insert(
        "shortDescription".to_string(),
        Value::String(BLOCK_MSG.to_owned()),
    );
    obj.insert(
        "description".to_string(),
        Value::String(BLOCK_MSG.to_owned()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_id_from_nested_publisher() {
        let ext = ExtensionLike {
            publisher: Some(PublisherLike {
                publisher_name: Some("microsoft".into()),
                name: None,
            }),
            publisher_name: None,
            extension_name: Some("vscode".into()),
            name: None,
            display_name: Some("Visual Studio Code".into()),
        };

        assert_eq!(extension_id(&ext), Some("microsoft.vscode".to_string()));
    }

    #[test]
    fn test_extension_id_from_flat_publisher() {
        let ext = ExtensionLike {
            publisher: None,
            publisher_name: Some("github".into()),
            extension_name: None,
            name: Some("copilot".into()),
            display_name: Some("GitHub Copilot".into()),
        };

        assert_eq!(extension_id(&ext), Some("github.copilot".to_string()));
    }

    #[test]
    fn test_extension_id_handles_whitespace() {
        let ext = ExtensionLike {
            publisher: None,
            publisher_name: Some("  publisher  ".into()),
            extension_name: Some("  extension  ".into()),
            name: None,
            display_name: Some("Test".into()),
        };

        assert_eq!(extension_id(&ext), Some("publisher.extension".to_string()));
    }

    #[test]
    fn test_rewrite_extension_object_preserves_original_name() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "displayName".to_string(),
            Value::String("Original Extension".to_string()),
        );

        let ext = ExtensionLike {
            publisher: None,
            publisher_name: Some("test".into()),
            extension_name: Some("test".into()),
            name: None,
            display_name: Some("Original Extension".into()),
        };

        rewrite_extension_object(&mut obj, &ext);

        assert_eq!(
            obj.get("displayName").and_then(|v| v.as_str()),
            Some("⛔ MALWARE: Original Extension")
        );
    }

    #[test]
    fn test_rewrite_extension_object_block_message_format() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "displayName".to_string(),
            Value::String("Test Extension".to_string()),
        );

        let ext = ExtensionLike {
            publisher: None,
            publisher_name: Some("test".into()),
            extension_name: Some("test".into()),
            name: None,
            display_name: Some("Test Extension".into()),
        };

        rewrite_extension_object(&mut obj, &ext);

        assert_eq!(
            obj.get("displayName").and_then(|v| v.as_str()),
            Some("⛔ MALWARE: Test Extension")
        );

        let description = obj.get("description").and_then(|v| v.as_str()).unwrap();
        assert!(description.contains("Aikido safe-chain"));
        assert!(description.contains("malware"));
        assert!(description.contains("blocked"));

        let short_description = obj
            .get("shortDescription")
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(description, short_description);
    }

    #[test]
    fn test_rewrite_marketplace_json_marks_matching_extension() {
        let body = r#"{
            "results": [
                {
                    "extensions": [
                        {
                            "publisher": { "publisherName": "pythoner" },
                            "extensionName": "pythontheme",
                            "displayName": "Python Theme"
                        }
                    ]
                }
            ]
        }"#;

        let modified =
            rewrite_marketplace_json_response_body_with_predicate(body.as_bytes(), |id| {
                id == "pythoner.pythontheme"
            })
            .expect("should rewrite");

        let val: Value = serde_json::from_slice(modified.as_ref()).unwrap();
        let ext = &val["results"][0]["extensions"][0];
        assert!(
            ext["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
        );
        assert!(ext.get("shortDescription").is_some());
        assert!(ext.get("description").is_some());
    }

    #[test]
    fn test_rewrite_marketplace_json_noop_when_no_match() {
        let body = br#"{"results":[{"extensions":[{"publisher":{"publisherName":"python"},"extensionName":"python","displayName":"Python"}]}]}"#;

        let modified = rewrite_marketplace_json_response_body_with_predicate(body, |_id| false);
        assert!(modified.is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_invalid_responses() {
        // Invalid JSON
        let body = b"not valid json";
        assert!(rewrite_marketplace_json_response_body_with_predicate(body, |_| true).is_none());

        // Empty body
        let body = b"";
        assert!(rewrite_marketplace_json_response_body_with_predicate(body, |_| true).is_none());

        // Missing expected structure
        let body = br#"{"results": []}"#;
        assert!(rewrite_marketplace_json_response_body_with_predicate(body, |_| true).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_early_return_missing_display_name_marker() {
        // Has publisher + extension name markers, but no displayName.
        let body = br#"{"results":[{"extensions":[{"publisher":{"publisherName":"pythoner"},"extensionName":"pythontheme"}]}]}"#;
        assert!(rewrite_marketplace_json_response_body_with_predicate(body, |_| true).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_early_return_missing_publisher_marker() {
        // Has displayName + extensionName markers, but no publisher/publisherName.
        let body = br#"{"results":[{"extensions":[{"extensionName":"pythontheme","displayName":"Python Theme"}]}]}"#;
        assert!(rewrite_marketplace_json_response_body_with_predicate(body, |_| true).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_early_return_missing_extension_name_marker() {
        // Has displayName + publisherName markers, but no name/extensionName.
        let body = br#"{"results":[{"extensions":[{"publisher":{"publisherName":"pythoner"},"displayName":"Python Theme"}]}]}"#;
        assert!(rewrite_marketplace_json_response_body_with_predicate(body, |_| true).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_case_insensitive_matching() {
        // Marketplace JSON uses mixed case (AddictedGuys.vscode-har-explorer)
        // Case-insensitive matching happens in is_extension_id_malware() method
        let body = r#"{
            "results": [
                {
                    "extensions": [
                        {
                            "publisher": { "publisherName": "AddictedGuys" },
                            "extensionName": "vscode-har-explorer",
                            "displayName": "HAR Explorer"
                        }
                    ]
                }
            ]
        }"#;

        // Malware predicate uses original case from JSON (case-insensitive matching in is_extension_id_malware)
        let modified =
            rewrite_marketplace_json_response_body_with_predicate(body.as_bytes(), |id| {
                id.eq_ignore_ascii_case("addictedguys.vscode-har-explorer")
            })
            .expect("should rewrite");

        let val: Value = serde_json::from_slice(modified.as_ref()).unwrap();
        let ext = &val["results"][0]["extensions"][0];
        assert!(
            ext["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
            "Extension with mixed case should be matched against lowercase malware list"
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_marks_multiple_malware_extensions() {
        let body = r#"{
            "results": [{
                "extensions": [
                    {
                        "publisher": { "publisherName": "malware1" },
                        "extensionName": "bad1",
                        "displayName": "Bad Extension 1"
                    },
                    {
                        "publisher": { "publisherName": "safe" },
                        "extensionName": "good",
                        "displayName": "Good Extension"
                    },
                    {
                        "publisher": { "publisherName": "malware2" },
                        "extensionName": "bad2",
                        "displayName": "Bad Extension 2"
                    }
                ]
            }]
        }"#;

        let modified =
            rewrite_marketplace_json_response_body_with_predicate(body.as_bytes(), |id| {
                id == "malware1.bad1" || id == "malware2.bad2"
            })
            .expect("should rewrite");

        let val: Value = serde_json::from_slice(modified.as_ref()).unwrap();
        let extensions = val["results"][0]["extensions"].as_array().unwrap();

        assert_eq!(extensions.len(), 3);

        let malware1 = extensions
            .iter()
            .find(|e| e["extensionName"].as_str() == Some("bad1"))
            .expect("malware1.bad1 should exist");
        assert!(
            malware1["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
            "malware1 displayName should start with malware marker, got: {}",
            malware1["displayName"].as_str().unwrap(),
        );

        let safe = extensions
            .iter()
            .find(|e| e["extensionName"].as_str() == Some("good"))
            .expect("safe.good should exist");
        assert_eq!(safe["displayName"].as_str().unwrap(), "Good Extension");

        let malware2 = extensions
            .iter()
            .find(|e| e["extensionName"].as_str() == Some("bad2"))
            .expect("malware2.bad2 should exist");
        assert!(
            malware2["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
            "malware2 displayName should start with malware marker, got: {}",
            malware2["displayName"].as_str().unwrap(),
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_nested_results() {
        let body = r#"{
            "results": [
                {
                    "extensions": [
                        {
                            "publisher": { "publisherName": "test1" },
                            "extensionName": "ext1",
                            "displayName": "Extension 1"
                        }
                    ]
                },
                {
                    "extensions": [
                        {
                            "publisher": { "publisherName": "malware" },
                            "extensionName": "bad",
                            "displayName": "Bad Extension"
                        }
                    ]
                }
            ]
        }"#;

        let modified =
            rewrite_marketplace_json_response_body_with_predicate(body.as_bytes(), |id| {
                id == "malware.bad"
            })
            .expect("should rewrite");

        let val: Value = serde_json::from_slice(modified.as_ref()).unwrap();
        let results = val["results"].as_array().unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0]["extensions"][0]["displayName"].as_str().unwrap(),
            "Extension 1"
        );
        assert!(
            results[1]["extensions"][0]["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:")
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_preserves_other_fields() {
        let body = r#"{
            "results": [{
                "extensions": [{
                    "publisher": { "publisherName": "test", "url": "https://example.com" },
                    "extensionName": "test",
                    "displayName": "Test",
                    "version": "1.0.0",
                    "lastUpdated": "2024-01-01",
                    "downloadCount": 1000
                }]
            }]
        }"#;

        let modified =
            rewrite_marketplace_json_response_body_with_predicate(body.as_bytes(), |id| {
                id == "test.test"
            })
            .expect("should rewrite");

        let val: Value = serde_json::from_slice(modified.as_ref()).unwrap();
        let ext = &val["results"][0]["extensions"][0];

        // Modified fields
        assert!(
            ext["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:")
        );
        assert!(ext.get("shortDescription").is_some());
        assert!(ext.get("description").is_some());

        // Preserved fields
        assert_eq!(ext["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(ext["lastUpdated"].as_str().unwrap(), "2024-01-01");
        assert_eq!(ext["downloadCount"].as_i64().unwrap(), 1000);
        assert_eq!(
            ext["publisher"]["url"].as_str().unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_large_response() {
        // Create a response with many extensions
        let mut extensions = Vec::new();
        for i in 0..100 {
            extensions.push(serde_json::json!({
                "publisher": { "publisherName": format!("publisher{}", i) },
                "extensionName": format!("ext{}", i),
                "displayName": format!("Extension {}", i)
            }));
        }

        let body_json = serde_json::json!({
            "results": [{
                "extensions": extensions
            }]
        });

        let body = serde_json::to_vec(&body_json).unwrap();

        // Mark the 50th extension as malware
        let modified = rewrite_marketplace_json_response_body_with_predicate(&body, |id| {
            id == "publisher50.ext50"
        })
        .expect("should rewrite");

        let val: Value = serde_json::from_slice(modified.as_ref()).unwrap();
        let result_extensions = val["results"][0]["extensions"].as_array().unwrap();

        assert_eq!(result_extensions.len(), 100);
        assert!(
            result_extensions[50]["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:")
        );
        assert_eq!(
            result_extensions[0]["displayName"].as_str().unwrap(),
            "Extension 0"
        );
        assert_eq!(
            result_extensions[99]["displayName"].as_str().unwrap(),
            "Extension 99"
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_depth_limit_stops_traversal() {
        // Build a deeply nested JSON object, deeper than the traversal limit.
        let mut root = serde_json::json!({});

        let mut current = &mut root;
        for _ in 0..(MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH + 10) {
            current
                .as_object_mut()
                .unwrap()
                .insert("n".to_string(), serde_json::json!({}));
            current = current.get_mut("n").unwrap();
        }

        // Place an extension-like object beyond the depth limit.
        current.as_object_mut().unwrap().insert(
            "extension".to_string(),
            serde_json::json!({
                "publisher": { "publisherName": "ms-python" },
                "extensionName": "python",
                "displayName": "Python"
            }),
        );

        let body = serde_json::to_vec(&root).unwrap();

        // Even if we treat every ID as malware, we should not rewrite because the traversal
        // never reaches the nested extension object.
        let modified = rewrite_marketplace_json_response_body_with_predicate(&body, |_id| true);
        assert!(modified.is_none());
    }
}
