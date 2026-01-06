use rama::{
    http::{BodyExtractExt as _, StatusCode, headers::Accept, service::client::HttpClientExt as _},
    telemetry::tracing,
};
use serde::Deserialize;

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
async fn test_vscode_https_install_asset_manifest_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/_apis/public/gallery/publishers/pythoner/vsextensions/pythontheme/2.7.5/assetbyname/Microsoft.VisualStudio.Code.Manifest")
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
async fn test_vscode_https_install_asset_signature_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://gallerycdn.vsassets.io/extensions/pythoner/pythontheme/2.7.5/Microsoft.VisualStudio.Services.VsixSignature")
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

    let payload: MarketplaceResponse = resp.try_into_json().await.unwrap();
    let extensions = &payload.results[0].extensions;

    let blocked = extensions
        .iter()
        .find(|ext| {
            ext.publisher.publisher_name == "pythoner" && ext.extension_name == "pythontheme"
        })
        .unwrap();

    assert_eq!(blocked.display_name, "⛔ MALWARE: Python Theme");
    assert!(blocked.short_description.is_some());
    assert!(blocked.description.is_some());

    let safe = extensions
        .iter()
        .find(|ext| ext.publisher.publisher_name == "python" && ext.extension_name == "python")
        .unwrap();

    assert_eq!(safe.display_name, "Python");
}

#[derive(Debug, Deserialize)]
struct MarketplaceResponse {
    results: Vec<MarketplaceResult>,
}

#[derive(Debug, Deserialize)]
struct MarketplaceResult {
    extensions: Vec<MarketplaceExtension>,
}

#[derive(Debug, Deserialize)]
struct MarketplaceExtension {
    publisher: MarketplacePublisher,

    #[serde(rename = "extensionName")]
    extension_name: String,

    #[serde(rename = "displayName")]
    display_name: String,

    #[serde(rename = "shortDescription")]
    short_description: Option<String>,

    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MarketplacePublisher {
    #[serde(rename = "publisherName")]
    publisher_name: String,
}
