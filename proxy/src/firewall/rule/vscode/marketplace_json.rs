use bytes::Bytes;
use rama::telemetry::tracing;
use serde::Deserialize;
use serde_json::{Map, Value};

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
pub(super) fn rewrite_marketplace_json_response_body(
    body_bytes: &Bytes,
    mut is_malware: impl FnMut(&str) -> bool,
) -> Option<Bytes> {
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
            tracing::warn!(
                error = %err,
                "Failed to serialize modified VSCode response; passing original through"
            );
            None
        }
    }
}

/// Recursively walks a JSON value and rewrites any objects that *look like* VS Code
/// Marketplace extension entries. This is deliberately schema-tolerant.
///
/// Notes:
/// - This will traverse the entire JSON response
/// - It is recursive
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
            // Traverse children first using a stable snapshot of keys.
            // This avoids mutating the same map while iterating its entries.
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

            // Now that traversal is complete, it's safe to rewrite the current object.
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

    tracing::warn!(
        package = %extension_id,
        "marked malware VSCode extension as blocked in API response"
    );

    rewrite_extension_object(obj, &extension_like);
    true
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PublisherLike {
    #[serde(rename = "publisherName")]
    publisher_name: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ExtensionLike {
    publisher: Option<PublisherLike>,

    #[serde(rename = "publisherName")]
    publisher_name: Option<String>,

    #[serde(rename = "extensionName")]
    extension_name: Option<String>,

    name: Option<String>,

    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

fn extension_id(ext: &ExtensionLike) -> Option<String> {
    let publisher = ext
        .publisher
        .as_ref()
        .and_then(|p| p.publisher_name.as_deref().or(p.name.as_deref()))
        .or(ext.publisher_name.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    let name = ext
        .extension_name
        .as_deref()
        .or(ext.name.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    Some(format!("{publisher}.{name}"))
}

fn rewrite_extension_object(obj: &mut Map<String, Value>, ext: &ExtensionLike) {
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
        Value::String(BLOCK_MSG.to_string()),
    );
    obj.insert(
        "description".to_string(),
        Value::String(BLOCK_MSG.to_string()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_id_from_nested_publisher() {
        let ext = ExtensionLike {
            publisher: Some(PublisherLike {
                publisher_name: Some("microsoft".to_string()),
                name: None,
            }),
            publisher_name: None,
            extension_name: Some("vscode".to_string()),
            name: None,
            display_name: Some("Visual Studio Code".to_string()),
        };

        assert_eq!(extension_id(&ext), Some("microsoft.vscode".to_string()));
    }

    #[test]
    fn test_extension_id_from_flat_publisher() {
        let ext = ExtensionLike {
            publisher: None,
            publisher_name: Some("github".to_string()),
            extension_name: None,
            name: Some("copilot".to_string()),
            display_name: Some("GitHub Copilot".to_string()),
        };

        assert_eq!(extension_id(&ext), Some("github.copilot".to_string()));
    }

    #[test]
    fn test_extension_id_handles_whitespace() {
        let ext = ExtensionLike {
            publisher: None,
            publisher_name: Some("  publisher  ".to_string()),
            extension_name: Some("  extension  ".to_string()),
            name: None,
            display_name: Some("Test".to_string()),
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
            publisher_name: Some("test".to_string()),
            extension_name: Some("test".to_string()),
            name: None,
            display_name: Some("Original Extension".to_string()),
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
            publisher_name: Some("test".to_string()),
            extension_name: Some("test".to_string()),
            name: None,
            display_name: Some("Test Extension".to_string()),
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
}
