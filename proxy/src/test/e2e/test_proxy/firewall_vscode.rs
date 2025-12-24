use rama::{
    Service,
    error::OpaqueError,
    http::{Request, Response, StatusCode, service::client::HttpClientExt as _},
};

pub(super) async fn test_vscode_http_plugin_malware_blocked(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://gallery.vsassets.io/extensions/pythoner/pythontheme/whatever?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

pub(super) async fn test_vscode_http_plugin_ok(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://gallery.vsassets.io/extensions/python/python/whatever?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

pub(super) async fn test_vscode_https_plugin_malware_blocked(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://gallery.vsassets.io/extensions/pythoner/pythontheme/whatever?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

pub(super) async fn test_vscode_https_plugin_ok(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://gallery.vsassets.io/extensions/python/python/whatever?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
