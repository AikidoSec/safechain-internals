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

    RuleVSCode::rewrite_extension_object(obj, "⛔ MALWARE: Test Extension");

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

    assert!(
        rule.rewrite_marketplace_json_response_body(b"not valid json")
            .is_none()
    );

    assert!(rule.rewrite_marketplace_json_response_body(b"").is_none());

    assert!(
        rule.rewrite_marketplace_json_response_body(br#"{\"results\": []}"#)
            .is_none()
    );

    assert!(rule
        .rewrite_marketplace_json_response_body(
            br#"{\"results\":[{\"extensions\":[{\"publisher\":{\"publisherName\":\"pythoner\"},\"extensionName\":\"pythontheme\"}]}]}"#
        )
        .is_none());

    assert!(rule
        .rewrite_marketplace_json_response_body(
            br#"{\"results\":[{\"extensions\":[{\"extensionName\":\"pythontheme\",\"displayName\":\"Python Theme\"}]}]}"#
        )
        .is_none());

    assert!(rule
        .rewrite_marketplace_json_response_body(
            br#"{\"results\":[{\"extensions\":[{\"publisher\":{\"publisherName\":\"pythoner\"},\"displayName\":\"Python Theme\"}]}]}"#
        )
        .is_none());
}

#[test]
fn test_rewrite_marketplace_json_depth_limit_stops_traversal() {
    let mut root = sonic_rs::json!({});

    let mut current = &mut root;
    for _ in 0..(MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH + 10) {
        current
            .as_object_mut()
            .unwrap()
            .insert("n", sonic_rs::json!({}));
        current = current.get_mut("n").unwrap();
    }

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
