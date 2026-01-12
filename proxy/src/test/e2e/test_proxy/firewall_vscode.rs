use rama::{
    http::{BodyExtractExt as _, StatusCode, headers::Accept, service::client::HttpClientExt as _},
    telemetry::tracing,
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_vsixpackage_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage")
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("malware"),
        "expected blocked response to mention malware, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_vspackage_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://marketplace.visualstudio.com/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/vspackage")
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("malware"),
        "expected blocked response to mention malware, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_manifest_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Code.Manifest")
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_signature_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;
    let resp = client
        .get("https://gallerycdn.vsassets.io/extensions/pythoner/pythontheme/2.7.5/Microsoft.VisualStudio.Services.VsixSignature")
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_vsix_file_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/files/pythoner/pythontheme/2.7.5/pythoner.pythontheme-2.7.5.vsix")
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("malware"),
        "expected blocked response to mention malware, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_non_install_path_passthrough() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Old-style URL shape that should no longer be blocked by request evaluation.
    let resp = client
        .get("https://gallery.vsassets.io/extensions/pythoner/pythontheme/whatever?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_marketplace_api_response_marks_only_malware_entries() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    let value: Value = sonic_rs::from_slice(payload.as_bytes()).unwrap();

    let results = value
        .get("results")
        .expect("marketplace response should have results");
    let results = results
        .as_array()
        .expect("marketplace response results should be an array");

    let first_result = results
        .first()
        .expect("marketplace response should have results[0]");
    let first_result = first_result
        .as_object()
        .expect("marketplace response results[0] should be an object");

    let extensions = first_result
        .get(&"extensions")
        .expect("marketplace response should have results[0].extensions");
    let extensions = extensions
        .as_array()
        .expect("marketplace response results[0].extensions should be an array");

    let is_extension = |ext: &Value, publisher: &str, extension: &str| {
        let Some(obj) = ext.as_object() else {
            return false;
        };

        let publisher_name = obj
            .get(&"publisher")
            .and_then(|p| p.as_object())
            .and_then(|p| p.get(&"publisherName"))
            .and_then(|v| v.as_str());

        let extension_name = obj.get(&"extensionName").and_then(|v| v.as_str());

        publisher_name == Some(publisher) && extension_name == Some(extension)
    };

    let blocked = extensions
        .iter()
        .find(|ext| is_extension(ext, "pythoner", "pythontheme"))
        .expect("expected to find pythoner.pythontheme extension in results");
    let blocked_obj = blocked.as_object().unwrap();

    assert_eq!(
        blocked_obj
            .get(&"displayName")
            .and_then(|v| v.as_str())
            .unwrap(),
        "⛔ MALWARE: Python Theme"
    );
    assert!(
        blocked_obj
            .get(&"shortDescription")
            .and_then(|v| v.as_str())
            .is_some()
    );

    let safe = extensions
        .iter()
        .find(|ext| is_extension(ext, "python", "python"))
        .expect("expected to find python.python extension in results");
    let safe_obj = safe.as_object().unwrap();

    assert_eq!(
        safe_obj
            .get(&"displayName")
            .and_then(|v| v.as_str())
            .unwrap(),
        "Python"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_subdomain_cdn_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Test that subdomain CDN URLs (e.g., publisher.gallerycdn.vsassets.io) are also intercepted
    // This is the actual pattern VS Code uses for downloading extensions
    let resp = client
        .get("https://pythoner.gallerycdn.vsassets.io/extensions/pythoner/pythontheme/2.7.5/1764597518125/Microsoft.VisualStudio.Services.VSIXPackage")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("malware"),
        "expected blocked response to mention malware, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_subdomain_gallery_api_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // VS Code can also download install assets from publisher-specific subdomains on
    // `*.gallery.vsassets.io` (not just `*.gallerycdn.vsassets.io`).
    let resp = client
        .get("https://pythoner.gallery.vsassets.io/_apis/public/gallery/publisher/pythoner/extension/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("malware"),
        "expected blocked response to mention malware, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_domain_gating_marketplace_json_rewrite() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Request from a non-matching domain
    let resp_other = client
        .get("https://example.com/_apis/public/gallery/extensionquery")
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp_other.status());
    let _payload_other = resp_other.try_into_string().await.unwrap();
    
    assert!(
        logs_contain("VSCode rule did not match response domain: passthrough"),
        "expected trace log indicating domain gating blocked processing"
    );
}
