use std::convert::Infallible;

use rama::{
    Service,
    http::{Request, Response, service::web::response::IntoResponse},
    service::service_fn,
};

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|_req: Request| async {
        let html = r#"<html><head><meta property="og:title" content="Mock Chrome Extension - Chrome Web Store"></head></html>"#;
        Ok::<_, Infallible>(html.into_response())
    })
}
