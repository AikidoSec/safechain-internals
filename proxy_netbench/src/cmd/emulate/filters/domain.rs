use std::{str::FromStr, sync::Arc};

use rama::{
    error::BoxError,
    http::Request,
    net::{address::Domain, http::RequestContext},
};
use safechain_proxy_lib::firewall::DomainMatcher;

#[derive(Debug, Default, Clone)]
pub struct DomainFilter(Option<Arc<DomainMatcher>>);

/// clap arg parser
pub fn parse_domain_filter(input: &str) -> Result<DomainFilter, BoxError> {
    let domains_result: Result<Vec<_>, _> = input
        .split(",")
        .filter(|s| !s.is_empty())
        .map(Domain::from_str)
        .collect();
    let matcher = DomainMatcher::from_iter(domains_result?);

    if matcher.iter().next().is_none() {
        Ok(DomainFilter(None))
    } else {
        Ok(DomainFilter(Some(Arc::new(matcher))))
    }
}

impl DomainFilter {
    pub fn match_req(&self, req: &Request) -> bool {
        let Some(matcher) = self.0.as_ref() else {
            // no matcher matches all
            return true;
        };

        RequestContext::try_from(req)
            .ok()
            .map(|ctx| ctx.host_with_port())
            .and_then(|v| v.host.into_domain())
            .map(|domain| matcher.is_match(&domain))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use rama::http::{self, Body};

    use super::*;

    fn req_with_absolute_uri(uri: &str) -> Request {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    fn req_with_relative_uri_and_host(host: &str) -> Request {
        Request::builder()
            .uri("/some/path")
            .header(http::header::HOST, host)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn match_req_no_matcher_matches_all_even_if_request_has_no_host() {
        let filter = parse_domain_filter("").unwrap();
        assert!(filter.match_req(&req_with_absolute_uri("http://example.com/")));

        // Relative URI without a Host header is typically not enough context.
        // With no matcher, we should still match all.
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert!(filter.match_req(&req));
    }

    #[test]
    fn match_req_matches_domain_from_absolute_uri_and_ignores_port() {
        let filter = parse_domain_filter("example.com").unwrap();

        assert!(filter.match_req(&req_with_absolute_uri("http://example.com/")));
        assert!(filter.match_req(&req_with_absolute_uri("http://example.com:8080/")));
        assert!(!filter.match_req(&req_with_absolute_uri("http://nope.com/")));
    }

    #[test]
    fn match_req_matches_domain_from_host_header_when_uri_is_relative() {
        let filter = parse_domain_filter("example.com").unwrap();

        assert!(filter.match_req(&req_with_relative_uri_and_host("example.com")));
        assert!(filter.match_req(&req_with_relative_uri_and_host("example.com:443")));
        assert!(!filter.match_req(&req_with_relative_uri_and_host("nope.com")));
    }

    #[test]
    fn match_req_returns_false_when_context_or_domain_cannot_be_derived() {
        let filter = parse_domain_filter("example.com").unwrap();

        // No absolute URI host and no Host header means host extraction should fail,
        // and match_req should fall back to false when a matcher exists.
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert!(!filter.match_req(&req));

        // An IP address is not a domain, so into_domain() should yield None,
        // leading to false as well.
        assert!(!filter.match_req(&req_with_absolute_uri("http://127.0.0.1/")));
        assert!(!filter.match_req(&req_with_relative_uri_and_host("127.0.0.1:8080")));
    }

    #[test]
    fn match_req_supports_multiple_domains_from_csv() {
        let filter = parse_domain_filter("example.com,foo.test,bar.org").unwrap();

        assert!(filter.match_req(&req_with_absolute_uri("http://example.com/")));
        assert!(filter.match_req(&req_with_absolute_uri("http://foo.test/")));
        assert!(filter.match_req(&req_with_absolute_uri("http://bar.org/")));
        assert!(!filter.match_req(&req_with_absolute_uri("http://nope.com/")));
    }
}
