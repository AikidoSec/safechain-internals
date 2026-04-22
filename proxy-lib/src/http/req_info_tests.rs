use std::convert::Infallible;

use rama::{
    Service,
    http::{Body, Response, Uri, proto::RequestExtensions, server::HttpServer},
    net::test_utils::client::MockConnectorService,
    rt::Executor,
    service::service_fn,
};

use super::*;

const REQUEST_META_TEST_URI: &str = "http://example.com/foo?bar=baz";
const REQUEST_META_TEST_HEADER_NAME: &str = "x-request-meta-test";
const REQUEST_META_TEST_HEADER_VALUE: &str = "present";

#[test]
fn test_try_get_domain_for_req() {
    struct TestCase {
        req: Request,
        expected_domain: Option<String>,
    }

    for test_case in [
        TestCase {
            req: Request::new(Body::empty()),
            expected_domain: None,
        },
        TestCase {
            req: Request::builder()
                .uri("http://example.com/foo")
                .body(Body::empty())
                .unwrap(),
            expected_domain: Some("example.com".to_owned()),
        },
        TestCase {
            req: Request::builder()
                .uri("/foo")
                .extension(ProxyTarget((Domain::from_static("aikido.dev"), 443).into()))
                .body(Body::empty())
                .unwrap(),
            expected_domain: Some("aikido.dev".to_owned()),
        },
    ] {
        let result = try_get_domain_for_req(&test_case.req).map(|d| d.to_string());
        assert_eq!(test_case.expected_domain, result);
    }
}

#[tokio::test]
async fn test_request_meta() {
    let expected_uri = Uri::from_static(REQUEST_META_TEST_URI);

    let mut connector = MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(|_req: Request| async move {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }))
    });
    connector.set_executor(Executor::default());

    let client = crate::http::client::new_http_client_for_internal_with_connector(
        Executor::default(),
        connector,
    )
    .unwrap();

    let req = Request::builder().uri(expected_uri.clone()).header(
        REQUEST_META_TEST_HEADER_NAME,
        REQUEST_META_TEST_HEADER_VALUE,
    );
    let req = req.body(Body::empty()).unwrap();
    let request_meta_uri = RequestMetaUri::from_request(&req);
    let request_meta_headers = RequestMetaHeaders::from_request(&req);
    let (parts, body) = req.into_parts();
    parts.extensions.insert(request_meta_uri);
    parts.extensions.insert(request_meta_headers);
    let req = Request::from_parts(parts, body);

    let res = client.serve(req).await.unwrap();
    let request_extensions = res.extensions().get_ref::<RequestExtensions>().unwrap();

    assert_eq!(
        request_extensions.get_ref().map(|RequestMetaUri(uri)| uri),
        Some(&expected_uri),
    );
    assert_eq!(
        request_extensions
            .get_ref()
            .and_then(|RequestMetaHeaders(headers)| headers.get(REQUEST_META_TEST_HEADER_NAME))
            .and_then(|value| value.to_str().ok()),
        Some(REQUEST_META_TEST_HEADER_VALUE),
    );
}
