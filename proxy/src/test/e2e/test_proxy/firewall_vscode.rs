use std::sync::LazyLock;

use tokio::sync::Mutex;

use rama::{
    http::{
        BodyExtractExt as _, HeaderValue, StatusCode,
        header::ACCEPT,
        headers::{Accept, HeaderEncode as _},
        service::client::HttpClientExt as _,
    },
    telemetry::tracing,
};
use serde_json::Value;

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_install_asset_vsixpackage_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage")
        .header(ACCEPT, accept_json_header_value())
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
async fn test_vscode_https_install_asset_manifest_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Code.Manifest")
        .header(ACCEPT, accept_json_header_value())
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
async fn test_vscode_https_install_asset_signature_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/extensions/pythoner/pythontheme/2.7.5/Microsoft.VisualStudio.Services.VsixSignature")
        .header(ACCEPT, accept_json_header_value())
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
async fn test_vscode_https_install_asset_vsix_file_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/files/pythoner/pythontheme/2.7.5/pythoner.pythontheme-2.7.5.vsix")
        .header(ACCEPT, accept_json_header_value())
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
    let json: Value = serde_json::from_str(&payload).unwrap();

    let extensions = json
        .get("results")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("extensions"))
        .and_then(|v| v.as_array())
        .unwrap();

    let blocked = extensions
        .iter()
        .find(|ext| {
            ext.get("publisher")
                .and_then(|p| p.get("publisherName"))
                .and_then(|v| v.as_str())
                == Some("pythoner")
                && ext.get("extensionName").and_then(|v| v.as_str()) == Some("pythontheme")
        })
        .unwrap();

    assert_eq!(
        blocked.get("displayName").and_then(|v| v.as_str()),
        Some("⛔ MALWARE: Python Theme")
    );
    assert!(blocked.get("shortDescription").is_some());
    assert!(blocked.get("description").is_some());

    let safe = extensions
        .iter()
        .find(|ext| {
            ext.get("publisher")
                .and_then(|p| p.get("publisherName"))
                .and_then(|v| v.as_str())
                == Some("python")
                && ext.get("extensionName").and_then(|v| v.as_str()) == Some("python")
        })
        .unwrap();

    assert_eq!(
        safe.get("displayName").and_then(|v| v.as_str()),
        Some("Python")
    );
}

static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn accept_json_header_value() -> HeaderValue {
    let accept = Accept::json();
    let mut values = Vec::new();
    accept.encode(&mut values);
    values
        .into_iter()
        .next()
        .expect("Accept::json should encode at least one value")
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_forced_malware_env_marks_ms_python_python() {
    let _lock = ENV_MUTEX.lock().await;
    unsafe { std::env::set_var("SAFECHAIN_FORCE_MALWARE_VSCODE", "ms-python.python") };

    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery_force_malware")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    let json: Value = serde_json::from_str(&payload).unwrap();

    let extensions = json
        .get("results")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("extensions"))
        .and_then(|v| v.as_array())
        .unwrap();

    let blocked = extensions
        .iter()
        .find(|ext| {
            ext.get("publisher")
                .and_then(|p| p.get("publisherName"))
                .and_then(|v| v.as_str())
                == Some("ms-python")
                && ext.get("extensionName").and_then(|v| v.as_str()) == Some("python")
        })
        .unwrap();

    assert!(
        blocked
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .starts_with("⛔ MALWARE:")
    );

    unsafe { std::env::remove_var("SAFECHAIN_FORCE_MALWARE_VSCODE") };
}
