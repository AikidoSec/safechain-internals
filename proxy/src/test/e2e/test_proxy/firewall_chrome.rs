use rama::{Service, http::StatusCode, telemetry::tracing};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_google_har_replay_blocked_plugin() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let req = e2e::har::parse_har_request(
        r##"{
    "method": "GET",
    "url": "https://clients2.google.com/service/update2/crx?response=redirect&os=mac&arch=arm64&os_arch=arm64&prod=chromecrx&prodchannel=&prodversion=143.0.7499.111&lang=en-US&acceptformat=crx3,puff&x=id%3Dlajondecmobodlejlcjllhojikagldgd%26installsource%3Dondemand%26uc&authuser=0",
    "httpVersion": "2",
    "cookies": [],
    "headers": [],
    "queryString": [],
    "postData": null,
    "headersSize": 4075,
    "bodySize": 0,
    "comment": "http(s) MITM egress client"
}"##,
    );

    let resp = client.serve(req).await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}
