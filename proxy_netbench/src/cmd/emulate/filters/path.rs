use std::{convert::Infallible, sync::Arc};

use rama::http::{Request, matcher::PathMatcher};

#[derive(Debug, Clone)]
pub struct PathFilter(Arc<[PathMatcher]>);

pub fn parse_path_filter(input: &str) -> Result<PathFilter, Infallible> {
    let path_matcher_result = input
        .split(",")
        .filter(|s| !s.is_empty())
        .map(PathMatcher::new)
        .collect();
    Ok(PathFilter(path_matcher_result))
}

impl PathFilter {
    pub(super) fn match_req(&self, req: &Request) -> bool {
        if self.0.is_empty() {
            // no matcher matches all
            return true;
        }

        let path = req.uri().path();
        for path_matcher in self.0.iter() {
            if path_matcher.matches_path(None, path) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::{Body, Request};

    fn req(path: &str) -> Request {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[test]
    fn parse_path_filter_empty_means_match_all() {
        let filter = parse_path_filter("").unwrap();
        assert!(filter.match_req(&req("/")));
        assert!(filter.match_req(&req("/foo")));
        assert!(filter.match_req(&req("/foo/bar")));
    }

    #[test]
    fn parse_path_filter_ignores_empty_segments_from_csv() {
        let filter = parse_path_filter(",,").unwrap();
        assert!(filter.match_req(&req("/")));
        assert!(filter.match_req(&req("/anything")));
    }

    #[test]
    fn match_req_exact_paths() {
        let filter = parse_path_filter("/,/foo,/foo/bar").unwrap();

        assert!(filter.match_req(&req("/")));
        assert!(filter.match_req(&req("/foo")));
        assert!(filter.match_req(&req("/foo/bar")));

        assert!(!filter.match_req(&req("/bar")));
        assert!(!filter.match_req(&req("/foo/baz")));
        assert!(!filter.match_req(&req("/foo/bar/baz")));
    }

    #[test]
    fn match_req_wildcard_suffix_matches_descendants() {
        let filter = parse_path_filter("/foo/*").unwrap();

        // Depending on PathMatcher semantics, "/foo/*" usually matches "/foo/<something>"
        // and deeper, but not "/foo" itself.
        assert!(!filter.match_req(&req("/foo")));
        assert!(!filter.match_req(&req("/foo/"))); // '*' matches something, trailing slashes do not count
        assert!(filter.match_req(&req("/foo/bar")));
        assert!(filter.match_req(&req("/foo/bar/baz")));

        assert!(!filter.match_req(&req("/")));
        assert!(!filter.match_req(&req("/bar")));
        assert!(!filter.match_req(&req("/foobar")));
    }

    #[test]
    fn match_req_path_params_single_segment() {
        let filter = parse_path_filter("/foo/{bar}/baz").unwrap();

        assert!(filter.match_req(&req("/foo/x/baz")));
        assert!(filter.match_req(&req("/foo/123/baz")));
        assert!(filter.match_req(&req("/foo/some-value/baz")));

        assert!(!filter.match_req(&req("/foo/x")));
        assert!(!filter.match_req(&req("/foo/x/baz/qux")));
        assert!(!filter.match_req(&req("/foo/x/qux")));
        assert!(!filter.match_req(&req("/foo//baz")));
    }

    #[test]
    fn match_req_path_params_with_wildcard_suffix() {
        let filter = parse_path_filter("/foo/{bar}/*").unwrap();

        // Must have at least one segment after the param to satisfy the trailing /*
        assert!(!filter.match_req(&req("/foo/x")));
        assert!(!filter.match_req(&req("/foo/x/"))); // '*' expects something
        assert!(filter.match_req(&req("/foo/x/baz")));
        assert!(filter.match_req(&req("/foo/x/baz/qux")));

        assert!(!filter.match_req(&req("/foo")));
        assert!(!filter.match_req(&req("/bar/x/baz")));
    }

    #[test]
    fn match_req_any_of_multiple_matchers() {
        let filter = parse_path_filter("/foo,/bar/*,/baz/{id}").unwrap();

        assert!(filter.match_req(&req("/foo")));
        assert!(filter.match_req(&req("/bar/x")));
        assert!(filter.match_req(&req("/bar/x/y")));
        assert!(filter.match_req(&req("/baz/123")));

        assert!(!filter.match_req(&req("/bar")));
        assert!(!filter.match_req(&req("/baz")));
        assert!(!filter.match_req(&req("/qux")));
    }

    #[test]
    fn match_req_uses_only_uri_path_not_query() {
        let filter = parse_path_filter("/foo").unwrap();

        assert!(filter.match_req(&req("/foo?x=y")));
        assert!(!filter.match_req(&req("/foo/bar?x=y")));
    }
}
