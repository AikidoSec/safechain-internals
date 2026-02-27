use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_open_vsx_org_vsixpackage_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://open-vsx.org/vscode/asset/malicious-publisher/evil-extension/1.0.0/Microsoft.VisualStudio.Services.VSIXPackage")
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
async fn test_cursor_api_vsixpackage_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://marketplace.cursorapi.com/open-vsx-mirror/vscode/asset/malicious-publisher/evil-extension/1.0.0/Microsoft.VisualStudio.Services.VSIXPackage")
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
async fn test_open_vsx_org_vsixpackage_safe_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://open-vsx.org/vscode/asset/redhat/java/1.30.0/Microsoft.VisualStudio.Services.VSIXPackage")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_cursor_api_vsixpackage_safe_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://marketplace.cursorapi.com/open-vsx-mirror/vscode/asset/redhat/java/1.30.0/Microsoft.VisualStudio.Services.VSIXPackage")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_open_vsx_org_manifest_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Manifest metadata should pass through even for the malware-listed extension
    let resp = client
        .get("https://open-vsx.org/vscode/asset/malicious-publisher/evil-extension/1.0.0/Microsoft.VisualStudio.Code.Manifest")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_open_vsx_org_vsix_signature_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://open-vsx.org/vscode/asset/malicious-publisher/evil-extension/1.0.0/Microsoft.VisualStudio.Services.VsixSignature")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
