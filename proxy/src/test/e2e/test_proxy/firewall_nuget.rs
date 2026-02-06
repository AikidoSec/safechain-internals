use rama::{
    http::{StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_https_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/safechaintest/0.0.1-security/safechaintest.0.0.1-security.nupkg?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.4/newtonsoft.json.13.0.4.nupkg")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
