use std::convert::Infallible;

use rama::{
    Service,
    http::{
        HeaderValue, Request, Response, StatusCode,
        header::CONTENT_TYPE,
        service::web::{
            Router,
            response::{Html, IntoResponse},
        },
    },
};

pub fn new_service(
    root_ca_pem: &'static [u8],
) -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new()
        .with_get("/", Html(STATIC_INDEX_PAGE))
        .with_get("/ping", StatusCode::OK)
        .with_get("/data/root.ca.pem", move || {
            let mut resp = root_ca_pem.into_response();
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            );
            std::future::ready(resp)
        })
}

const STATIC_INDEX_PAGE: &str = include_str!("./hijack_index.html");
