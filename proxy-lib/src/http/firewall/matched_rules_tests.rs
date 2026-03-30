use std::sync::Arc;

use super::{FirewallHttpResponsePayloadInspectionRules, FirewallHttpRules};
use crate::http::firewall::rule::{HttpResponseMatcherView, Rule};
use rama::{
    http::{Request, Response, StatusCode, service::web::response::IntoResponse as _},
    net::address::Domain,
};

#[derive(Debug, Clone, Copy)]
enum ResponseMatch {
    Always,
    Never,
    SuccessStatus,
}

#[derive(Debug, Clone, Copy)]
struct TestRule {
    request_match: bool,
    response_match: ResponseMatch,
}

impl TestRule {
    const fn request_match(request_match: bool) -> Self {
        Self {
            request_match,
            response_match: ResponseMatch::Always,
        }
    }

    const fn with_response_match(response_match: ResponseMatch) -> Self {
        Self {
            request_match: true,
            response_match,
        }
    }
}

impl Rule for TestRule {
    fn match_domain(&self, _: &Domain) -> bool {
        false
    }

    #[cfg(feature = "pac")]
    fn collect_pac_domains(&self, _: &mut crate::http::firewall::pac::PacScriptGenerator) {}

    fn match_http_response_payload_inspection_request(
        &self,
        _: crate::http::firewall::rule::HttpRequestMatcherView<'_>,
    ) -> bool {
        self.request_match
    }

    fn match_http_response_payload_inspection_response(
        &self,
        resp: HttpResponseMatcherView<'_>,
    ) -> bool {
        match self.response_match {
            ResponseMatch::Always => true,
            ResponseMatch::Never => false,
            ResponseMatch::SuccessStatus => resp.status.is_success(),
        }
    }
}

fn http_rules(rules: impl IntoIterator<Item = TestRule>) -> FirewallHttpRules {
    FirewallHttpRules(Arc::from(
        rules
            .into_iter()
            .map(TestRule::into_dyn)
            .collect::<Vec<_>>(),
    ))
}

fn response_rules(
    rules: impl IntoIterator<Item = TestRule>,
) -> FirewallHttpResponsePayloadInspectionRules {
    FirewallHttpResponsePayloadInspectionRules(Arc::from(
        rules
            .into_iter()
            .map(TestRule::into_dyn)
            .collect::<Vec<_>>(),
    ))
}

#[test]
fn requires_response_payload_inspection_when_any_rule_opted_in() {
    let rules = http_rules([
        TestRule::request_match(false),
        TestRule::request_match(true),
    ]);

    assert!(rules.has_http_response_payload_inspection_match(&Request::new(())));
}

#[test]
fn does_not_require_response_payload_inspection_by_default() {
    let rules = http_rules([TestRule::request_match(false)]);

    assert!(!rules.has_http_response_payload_inspection_match(&Request::new(())));
}

#[test]
fn response_matcher_can_disable_response_payload_inspection() {
    let rules = response_rules([TestRule::with_response_match(ResponseMatch::SuccessStatus)]);

    assert!(rules.matches_http_response_payload_inspection(&Response::new(())));
    assert!(
        !rules.matches_http_response_payload_inspection(&StatusCode::NOT_FOUND.into_response())
    );
}

#[test]
fn response_payload_inspection_uses_union_across_matched_rules() {
    let request_rules = http_rules([
        TestRule::with_response_match(ResponseMatch::Never),
        TestRule::with_response_match(ResponseMatch::SuccessStatus),
    ]);

    let response_rules = request_rules
        .select_http_response_payload_inspection_rules(&Request::new(()))
        .expect("at least one rule should match request phase");

    assert!(response_rules.matches_http_response_payload_inspection(&Response::new(())));
    assert!(
        !response_rules
            .matches_http_response_payload_inspection(&StatusCode::NOT_FOUND.into_response())
    );
}
