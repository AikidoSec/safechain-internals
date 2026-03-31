use rama::{
    http::{BodyExtractExt as _, StatusCode, headers::Accept, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

/// These must match the entries served by `mock_server::malware_list::released_vscode`.
const FRESH_EXTENSION_PUBLISHER: &str = "newpublisher";
const FRESH_EXTENSION_NAME: &str = "freshextension";
const FRESH_EXTENSION_VERSION: &str = "1.0.0";

const SAFE_EXTENSION_URL: &str = "https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage";

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
async fn test_vscode_https_install_asset_allowed_by_endpoint_policy_exception() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-pythoner-pythontheme-vscode",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "pythoner.pythontheme" is malware, but the allowed_packages exception overrides the malware check.
    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-vscode", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // "python.python" is not malware, but block_all_installs blocks it.
    let resp = client.get(SAFE_EXTENSION_URL).send().await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_blocked_by_endpoint_policy_rejected_package() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-reject-python-python-vscode",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "python.python" is in rejected_packages — blocked even though it's not malware.
    let resp = client.get(SAFE_EXTENSION_URL).send().await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_blocked_by_endpoint_policy_request_installs() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-request-installs-vscode",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "python.python" is not malware, but request_installs requires approval for all installs.
    let resp = client.get(SAFE_EXTENSION_URL).send().await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
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
async fn test_vscode_https_install_asset_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // newpublisher.freshextension is in the released packages list (released far in the future
    // relative to a 24h cutoff) and is NOT in the malware list — should be blocked as new package.
    let url = format!(
        "https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/{FRESH_EXTENSION_PUBLISHER}/vsextensions/{FRESH_EXTENSION_NAME}/{FRESH_EXTENSION_VERSION}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    );
    let resp = client
        .get(url)
        .typed_header(Accept::json())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("24 hours") || payload.to_lowercase().contains("vetted"),
        "expected blocked response to mention 24-hour vetting, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_new_package_not_blocked_via_policy_cutoff() {
    // The policy sets minimum_allowed_age_timestamp far in the future (year ~2286), making the
    // cutoff larger than our test entry's released_on (year ~2255) — so the extension is no
    // longer considered "recent" and is allowed through.
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-vscode",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!(
        "https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/{FRESH_EXTENSION_PUBLISHER}/vsextensions/{FRESH_EXTENSION_NAME}/{FRESH_EXTENSION_VERSION}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    );
    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
