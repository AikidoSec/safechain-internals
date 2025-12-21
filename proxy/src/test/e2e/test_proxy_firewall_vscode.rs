use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    net::{
        Protocol,
        address::ProxyAddress,
        user::{ProxyCredential, credentials::basic},
    },
    telemetry::tracing,
    tls::boring::core::x509::X509,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_http_plugin_malware_blocked() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, false).await;

    let resp = client
        .get("http://gallery.vsassets.io/extensions/pythoner/pythontheme/whatever?a=b")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_http_plugin_ok() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, false).await;

    let resp = client
        .get("http://gallery.vsassets.io/extensions/python/python/whatever?a=b")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_plugin_malware_blocked() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, true).await;

    let resp = client
        .get("https://gallery.vsassets.io/extensions/pythoner/pythontheme/whatever?a=b")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_vscode_https_plugin_ok() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, true).await;

    let resp = client
        .get("https://gallery.vsassets.io/extensions/python/python/whatever?a=b")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
