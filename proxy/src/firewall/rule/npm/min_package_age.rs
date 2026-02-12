use rama::{
    http::{
        HeaderValue, Request, Response,
        headers::{Accept, HeaderMapExt},
    },
    telemetry::tracing,
};

pub(in crate::firewall) struct MinPackageAge {}

impl MinPackageAge {
    pub fn modify_request_headers(req: &mut Request) {
        let Some(accept_is_npm_info) = req.headers().typed_get().map(|accept: Accept| {
            accept
                .0
                .iter()
                .any(|mime| mime.value.subtype() == "vnd.npm.install-v1")
        }) else {
            return;
        };

        if !accept_is_npm_info {
            return;
        }

        if let Ok(replacement_accept_header) = HeaderValue::from_str("application/json") {
            tracing::debug!(
                "modified accept: application/vnd.npm.install-v1+json header to application/json",
            );
            let _ = &req
                .headers_mut()
                .insert("accept", replacement_accept_header);
        }
    }

    pub fn remove_new_packages(resp: &mut Response) {}
}

#[cfg(test)]
mod tests {

    use super::*;

    use rama::http::Body;

    fn make_request(accept: Option<&str>) -> Request {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        if let Some(accept) = accept {
            req.headers_mut()
                .insert("accept", HeaderValue::from_str(accept).unwrap());
        }
        req
    }

    #[test]
    fn replaces_npm_install_accept_header() {
        let mut req = make_request(Some("application/vnd.npm.install-v1+json"));
        MinPackageAge::modify_request_headers(&mut req);
        assert_eq!(req.headers().get("accept").unwrap(), "application/json");
    }

    #[test]
    fn no_accept_header_is_unchanged() {
        let mut req = make_request(None);
        MinPackageAge::modify_request_headers(&mut req);
        assert!(req.headers().get("accept").is_none());
    }

    #[test]
    fn non_matching_accept_header_is_unchanged() {
        let mut req = make_request(Some("application/json"));
        MinPackageAge::modify_request_headers(&mut req);
        assert_eq!(req.headers().get("accept").unwrap(), "application/json");
    }

    #[test]
    fn unrelated_accept_header_is_unchanged() {
        let mut req = make_request(Some("text/html"));
        MinPackageAge::modify_request_headers(&mut req);
        assert_eq!(req.headers().get("accept").unwrap(), "text/html");
    }
}
