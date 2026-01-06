use memchr::memmem;
use rama::bytes::Bytes;
use rama::telemetry::tracing;
use rama::utils::str::smol_str::{SmolStr, format_smolstr};
use sonic_rs::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value};

use super::RuleVSCode;

const MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH: usize = 32;

impl RuleVSCode {
    /// Attempts to parse a VS Code Marketplace JSON response body and rewrites it in-place
    /// to mark extensions as malware when they match the malware list.
    pub(super) fn rewrite_marketplace_json_response_body(
        &self,
        body_bytes: &[u8],
    ) -> Option<Bytes> {
        memmem::find(body_bytes, br#""displayName""#)?;

        if memmem::find(body_bytes, br#""publisherName""#).is_none()
            && memmem::find(body_bytes, br#""publisher""#).is_none()
        {
            return None;
        }

        if memmem::find(body_bytes, br#""extensionName""#).is_none()
            && memmem::find(body_bytes, br#""name""#).is_none()
        {
            return None;
        }

        let mut value: Value = match sonic_rs::from_slice(body_bytes) {
            Ok(val) => val,
            Err(err) => {
                tracing::trace!(error = %err, "VSCode response: failed to parse JSON; passthrough");
                return None;
            }
        };

        let modified = self.mark_extensions_recursive(&mut value, 0);
        if !modified {
            return None;
        }

        match sonic_rs::to_vec(&value) {
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
    fn mark_extensions_recursive(&self, value: &mut Value, depth: usize) -> bool {
        if depth >= MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH {
            tracing::trace!(
                max_depth = MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH,
                "VSCode response JSON traversal depth limit reached; stopping traversal"
            );
            return false;
        }

        if let Some(arr) = value.as_array_mut() {
            let mut modified = false;

            for child in arr.iter_mut() {
                modified |= self.mark_extensions_recursive(child, depth + 1);
            }

            return modified;
        }

        if let Some(obj) = value.as_object_mut() {
            let mut modified = false;

            for (_, child) in obj.iter_mut() {
                modified |= self.mark_extensions_recursive(child, depth + 1);
            }

            modified |= self.mark_extension_if_malware(value);
            return modified;
        }

        false
    }

    /// If `value` is a JSON object that looks like a VS Code Marketplace extension entry,
    /// rewrite it in-place when it matches the malware predicate.
    ///
    /// - The object must contain enough fields to build an extension id (`publisher.name`).
    /// - And it must also contain an "extension-ish" field (`displayName`).
    ///
    /// Returns `true` if the object was rewritten.
    fn mark_extension_if_malware(&self, value: &mut Value) -> bool {
        let (display_name_str, extension_id) = {
            let Some(obj) = value.as_object() else {
                return false;
            };

            let display_name = match obj.get(&"displayName").and_then(|v| v.as_str()) {
                Some(name) => name,
                None => return false,
            };

            let extension_id = match Self::extract_extension_id(obj) {
                Some(id) => id,
                None => return false,
            };

            if !self.is_extension_id_malware(extension_id.as_str()) {
                return false;
            }

            (display_name.to_string(), extension_id)
        };

        tracing::info!(
            package = %extension_id,
            "marked malware VSCode extension as blocked in API response"
        );

        if let Some(obj_mut) = value.as_object_mut() {
            Self::rewrite_extension_object(obj_mut, &display_name_str);
        }
        true
    }

    /// Extracts the extension ID from a JSON object by looking up publisher and name fields.
    /// Returns None if required fields are missing or invalid.
    fn extract_extension_id(obj: &sonic_rs::Object) -> Option<SmolStr> {
        fn get_trimmed<'a>(obj: &'a sonic_rs::Object, key: &str) -> Option<&'a str> {
            obj.get(&key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        }

        let publisher = obj
            .get(&"publisher")
            .and_then(|p| p.as_object())
            .and_then(|p| get_trimmed(p, "publisherName").or_else(|| get_trimmed(p, "name")))
            .or_else(|| get_trimmed(obj, "publisherName"))?;

        let name = get_trimmed(obj, "extensionName").or_else(|| get_trimmed(obj, "name"))?;

        Some(format_smolstr!("{publisher}.{name}"))
    }

    fn rewrite_extension_object(obj: &mut sonic_rs::Object, original_name: &str) {
        let malware_display = format!("⛔ MALWARE: {original_name}");
        obj.insert("displayName", Value::from(malware_display.as_str()));

        const BLOCK_MSG: &str = "This extension has been marked as malware by Aikido safe-chain. Installation will be blocked.";

        obj.insert("shortDescription", Value::from(BLOCK_MSG));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_extension_id_variants() {
        let nested = sonic_rs::json!({
            "publisher": { "publisherName": "microsoft" },
            "extensionName": "vscode",
            "displayName": "Visual Studio Code"
        });
        assert_eq!(
            RuleVSCode::extract_extension_id(nested.as_object().unwrap()),
            Some(SmolStr::new("microsoft.vscode"))
        );

        let flat = sonic_rs::json!({
            "publisherName": "github",
            "name": "copilot",
            "displayName": "GitHub Copilot"
        });
        assert_eq!(
            RuleVSCode::extract_extension_id(flat.as_object().unwrap()),
            Some(SmolStr::new("github.copilot"))
        );

        let whitespace = sonic_rs::json!({
            "publisherName": "  publisher  ",
            "extensionName": "  extension  ",
            "displayName": "Test"
        });
        assert_eq!(
            RuleVSCode::extract_extension_id(whitespace.as_object().unwrap()),
            Some(SmolStr::new("publisher.extension"))
        );
    }

    #[test]
    fn test_rewrite_extension_object_invariants() {
        let mut json = sonic_rs::json!({
            "displayName": "Test Extension"
        });
        let obj = json.as_object_mut().unwrap();

        RuleVSCode::rewrite_extension_object(obj, "Test Extension");

        assert_eq!(
            obj.get(&"displayName").and_then(|v| v.as_str()),
            Some("⛔ MALWARE: Test Extension")
        );

        let short_description = obj
            .get(&"shortDescription")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(short_description.contains("Aikido safe-chain"));
        assert!(short_description.contains("malware"));
        assert!(short_description.contains("blocked"));

        // Description should not be modified (VS Code API often returns null here)
        assert!(obj.get(&"description").is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_rewrites_only_matching_extension_and_preserves_fields() {
        let body = r#"{
            "results": [
                {
                    "extensions": [
                        {
                            "publisher": { "publisherName": "AddictedGuys", "url": "https://example.com" },
                            "extensionName": "vscode-har-explorer",
                            "displayName": "HAR Explorer",
                            "version": "1.2.3"
                        },
                        {
                            "publisher": { "publisherName": "safe" },
                            "extensionName": "good",
                            "displayName": "Good Extension",
                            "downloadCount": 123
                        }
                    ]
                }
            ]
        }"#;

        // Store lowercase in malware list; matching should be case-insensitive.
        let rule = RuleVSCode::new_test(["addictedguys.vscode-har-explorer"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(body.as_bytes())
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
        let extensions = val["results"][0]["extensions"].as_array().unwrap();

        let malware = &extensions[0];
        assert!(
            malware["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
        );
        assert!(malware.get("shortDescription").is_some());
        assert_eq!(malware["version"].as_str().unwrap(), "1.2.3");
        assert_eq!(
            malware["publisher"]["url"].as_str().unwrap(),
            "https://example.com"
        );

        let safe = &extensions[1];
        assert_eq!(safe["displayName"].as_str().unwrap(), "Good Extension");
        assert!(safe.get("shortDescription").is_none());
        assert_eq!(safe["downloadCount"].as_i64().unwrap(), 123);
    }

    #[test]
    fn test_rewrite_marketplace_json_noop_when_no_match() {
        let body = br#"{"results":[{"extensions":[{"publisher":{"publisherName":"python"},"extensionName":"python","displayName":"Python"}]}]}"#;

        let rule = RuleVSCode::new_test::<[&str; 0], _>([]);
        let modified = rule.rewrite_marketplace_json_response_body(body);
        assert!(modified.is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_robustness_noop_cases() {
        let rule = RuleVSCode::new_test(["any.extension"]);

        // Invalid JSON
        assert!(
            rule.rewrite_marketplace_json_response_body(b"not valid json")
                .is_none()
        );

        // Empty body
        assert!(rule.rewrite_marketplace_json_response_body(b"").is_none());

        // Missing expected structure
        assert!(
            rule.rewrite_marketplace_json_response_body(br#"{\"results\": []}"#)
                .is_none()
        );

        // Has publisher + extension name markers, but no displayName.
        assert!(rule
            .rewrite_marketplace_json_response_body(
                br#"{\"results\":[{\"extensions\":[{\"publisher\":{\"publisherName\":\"pythoner\"},\"extensionName\":\"pythontheme\"}]}]}"#
            )
            .is_none());

        // Has displayName + extensionName markers, but no publisher/publisherName.
        assert!(rule
            .rewrite_marketplace_json_response_body(
                br#"{\"results\":[{\"extensions\":[{\"extensionName\":\"pythontheme\",\"displayName\":\"Python Theme\"}]}]}"#
            )
            .is_none());

        // Has displayName + publisherName markers, but no name/extensionName.
        assert!(rule
            .rewrite_marketplace_json_response_body(
                br#"{\"results\":[{\"extensions\":[{\"publisher\":{\"publisherName\":\"pythoner\"},\"displayName\":\"Python Theme\"}]}]}"#
            )
            .is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_depth_limit_stops_traversal() {
        // Build a deeply nested JSON object, deeper than the traversal limit.
        let mut root = sonic_rs::json!({});

        let mut current = &mut root;
        for _ in 0..(MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH + 10) {
            current
                .as_object_mut()
                .unwrap()
                .insert("n", sonic_rs::json!({}));
            current = current.get_mut("n").unwrap();
        }

        // Place an extension-like object beyond the depth limit.
        current.as_object_mut().unwrap().insert(
            "extension",
            sonic_rs::json!({
                "publisher": { "publisherName": "ms-python" },
                "extensionName": "python",
                "displayName": "Python"
            }),
        );

        let body = sonic_rs::to_vec(&root).unwrap();

        // Even if we have malware in the list, we should not rewrite because the traversal
        // never reaches the nested extension object.
        let rule = RuleVSCode::new_test(["ms-python.python"]);
        let modified = rule.rewrite_marketplace_json_response_body(&body);
        assert!(modified.is_none());
    }
}
