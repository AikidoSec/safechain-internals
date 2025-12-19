use std::borrow::Cow;

use rama::{
    extensions::ExtensionsRef,
    http::Request,
    net::{address::Domain, http::RequestContext, proxy::ProxyTarget},
};

pub(super) fn try_get_domain_for_req(req: &Request) -> Option<Cow<'_, Domain>> {
    match req.extensions().get() {
        Some(ProxyTarget(target)) => target.host.as_domain().map(Cow::Borrowed),
        None => RequestContext::try_from(req)
            .ok()
            .map(|ctx| ctx.host_with_port())
            .and_then(|v| v.host.into_domain())
            .map(Cow::Owned),
    }
}

#[cfg(test)]
mod tests {
    use rama::http::Body;

    use super::*;

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
}
