use memchr::memmem;
use rama::bytes::Bytes;
use rama::telemetry::tracing;
use sonic_rs::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value};

use super::RuleVSCode;

const MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH: usize = 32;

impl RuleVSCode {
    /// Attempts to parse a VS Code Marketplace JSON response body and rewrites it in-place
    /// to mark extensions as malware when they match the malware list.
    ///
    /// This is intentionally tolerant:
    /// - It can handle the common `extensionquery` response shape (`results -> [ { extensions: [...] } ]`).
    /// - It also scans nested JSON objects and only rewrites objects that *look like* extension entries.
    ///
    /// # Returns
    /// - `Some(Bytes)` with the rewritten JSON if any changes were made.
    /// - `None` if parsing failed or no rewrite was needed.
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
            return arr.iter_mut().fold(false, |acc, child| {
                self.mark_extensions_recursive(child, depth + 1) || acc
            });
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

            (display_name.to_string(), extension_id)
        };

        if !self.is_extension_id_malware(&extension_id) {
            return false;
        }

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
    fn extract_extension_id(obj: &sonic_rs::Object) -> Option<String> {
        // Try to get publisher name from nested publisher object or flat publisherName field
        let publisher = obj
            .get(&"publisher")
            .and_then(|p| p.as_object())
            .and_then(|p| {
                p.get(&"publisherName")
                    .and_then(|v| v.as_str())
                    .or_else(|| p.get(&"name").and_then(|v| v.as_str()))
            })
            .or_else(|| obj.get(&"publisherName").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        // Try to get extension name from extensionName or name field
        let name = obj
            .get(&"extensionName")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get(&"name").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        Some(format!("{publisher}.{name}"))
    }

    fn rewrite_extension_object(obj: &mut sonic_rs::Object, original_name: &str) {
        let malware_display = format!("⛔ MALWARE: {original_name}");
        obj.insert("displayName", Value::from(malware_display.as_str()));

        const BLOCK_MSG: &str = "This extension has been marked as malware by Aikido safe-chain. Installation will be blocked.";

        obj.insert("shortDescription", Value::from(BLOCK_MSG));
        obj.insert("description", Value::from(BLOCK_MSG));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_extension_id_from_nested_publisher() {
        let json = sonic_rs::json!({
            "publisher": {
                "publisherName": "microsoft"
            },
            "extensionName": "vscode",
            "displayName": "Visual Studio Code"
        });
        let obj = json.as_object().unwrap();

        assert_eq!(
            RuleVSCode::extract_extension_id(obj),
            Some("microsoft.vscode".to_string())
        );
    }

    #[test]
    fn test_extract_extension_id_from_flat_publisher() {
        let json = sonic_rs::json!({
            "publisherName": "github",
            "name": "copilot",
            "displayName": "GitHub Copilot"
        });
        let obj = json.as_object().unwrap();

        assert_eq!(
            RuleVSCode::extract_extension_id(obj),
            Some("github.copilot".to_string())
        );
    }

    #[test]
    fn test_extract_extension_id_handles_whitespace() {
        let json = sonic_rs::json!({
            "publisherName": "  publisher  ",
            "extensionName": "  extension  ",
            "displayName": "Test"
        });
        let obj = json.as_object().unwrap();

        assert_eq!(
            RuleVSCode::extract_extension_id(obj),
            Some("publisher.extension".to_string())
        );
    }

    #[test]
    fn test_rewrite_extension_object_preserves_original_name() {
        let mut json = sonic_rs::json!({
            "displayName": "Original Extension"
        });
        let obj = json.as_object_mut().unwrap();

        RuleVSCode::rewrite_extension_object(obj, "Original Extension");

        assert_eq!(
            obj.get(&"displayName").and_then(|v| v.as_str()),
            Some("⛔ MALWARE: Original Extension")
        );
    }

    #[test]
    fn test_rewrite_extension_object_block_message_format() {
        let mut json = sonic_rs::json!({
            "displayName": "Test Extension"
        });
        let obj = json.as_object_mut().unwrap();

        RuleVSCode::rewrite_extension_object(obj, "Test Extension");

        assert_eq!(
            obj.get(&"displayName").and_then(|v| v.as_str()),
            Some("⛔ MALWARE: Test Extension")
        );

        let description = obj.get(&"description").and_then(|v| v.as_str()).unwrap();
        assert!(description.contains("Aikido safe-chain"));
        assert!(description.contains("malware"));
        assert!(description.contains("blocked"));

        let short_description = obj
            .get(&"shortDescription")
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

        let rule = RuleVSCode::new_test(["pythoner.pythontheme"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(body.as_bytes())
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
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

        let rule = RuleVSCode::new_test::<[&str; 0], _>([]);
        let modified = rule.rewrite_marketplace_json_response_body(body);
        assert!(modified.is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_invalid_responses() {
        // Use a malware list that would match everything if JSON was valid
        let rule = RuleVSCode::new_test(["any.extension"]);

        // Invalid JSON
        let body = b"not valid json";
        assert!(rule.rewrite_marketplace_json_response_body(body).is_none());

        // Empty body
        let body = b"";
        assert!(rule.rewrite_marketplace_json_response_body(body).is_none());

        // Missing expected structure
        let body = br#"{"results": []}"#;
        assert!(rule.rewrite_marketplace_json_response_body(body).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_early_return_missing_display_name_marker() {
        let rule = RuleVSCode::new_test(["pythoner.pythontheme"]);

        // Has publisher + extension name markers, but no displayName.
        let body = br#"{"results":[{"extensions":[{"publisher":{"publisherName":"pythoner"},"extensionName":"pythontheme"}]}]}"#;
        assert!(rule.rewrite_marketplace_json_response_body(body).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_early_return_missing_publisher_marker() {
        let rule = RuleVSCode::new_test(["pythoner.pythontheme"]);

        // Has displayName + extensionName markers, but no publisher/publisherName.
        let body = br#"{"results":[{"extensions":[{"extensionName":"pythontheme","displayName":"Python Theme"}]}]}"#;
        assert!(rule.rewrite_marketplace_json_response_body(body).is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_early_return_missing_extension_name_marker() {
        let rule = RuleVSCode::new_test(["pythoner.pythontheme"]);

        // Has displayName + publisherName markers, but no name/extensionName.
        let body = br#"{"results":[{"extensions":[{"publisher":{"publisherName":"pythoner"},"displayName":"Python Theme"}]}]}"#;
        assert!(rule.rewrite_marketplace_json_response_body(body).is_none());
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

        // Store lowercase in malware list; is_extension_id_malware() does case-insensitive matching
        let rule = RuleVSCode::new_test(["addictedguys.vscode-har-explorer"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(body.as_bytes())
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
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

        let rule = RuleVSCode::new_test(["malware1.bad1", "malware2.bad2"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(body.as_bytes())
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
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

        let rule = RuleVSCode::new_test(["malware.bad"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(body.as_bytes())
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
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

        let rule = RuleVSCode::new_test(["test.test"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(body.as_bytes())
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
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
            extensions.push(sonic_rs::json!({
                "publisher": { "publisherName": format!("publisher{}", i) },
                "extensionName": format!("ext{}", i),
                "displayName": format!("Extension {}", i)
            }));
        }

        let body_json = sonic_rs::json!({
            "results": [{
                "extensions": extensions
            }]
        });

        let body = sonic_rs::to_vec(&body_json).unwrap();

        // Mark the 50th extension as malware
        let rule = RuleVSCode::new_test(["publisher50.ext50"]);
        let modified = rule
            .rewrite_marketplace_json_response_body(&body)
            .expect("should rewrite");

        let val: Value = sonic_rs::from_slice(modified.as_ref()).unwrap();
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
