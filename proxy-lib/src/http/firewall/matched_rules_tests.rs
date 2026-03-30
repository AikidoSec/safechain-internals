use std::sync::Arc;

use super::{FirewallHttpResponsePayloadInspectionRules, FirewallHttpRules};
use crate::http::firewall::rule::Rule;
use rama::{
    http::{Request, Response, StatusCode, service::web::response::IntoResponse as _},
    net::address::Domain,
};

#[derive(Debug)]
struct DummyRule {
    requires_payload_inspection: bool,
}

impl Rule for DummyRule {
    fn match_domain(&self, _: &Domain) -> bool {
        false
    }

    #[cfg(feature = "pac")]
    fn collect_pac_domains(&self, _: &mut crate::http::firewall::pac::PacScriptGenerator) {}

    fn match_http_response_payload_inspection_request(
        &self,
        _: crate::http::firewall::rule::HttpRequestMatcherView<'_>,
    ) -> bool {
        self.requires_payload_inspection
    }
}

#[test]
fn requires_response_payload_inspection_when_any_rule_opted_in() {
    let rules = FirewallHttpRules(Arc::from([
        DummyRule {
            requires_payload_inspection: false,
        }
        .into_dyn(),
        DummyRule {
            requires_payload_inspection: true,
        }
        .into_dyn(),
    ]));

    assert!(rules.has_http_response_payload_inspection_match(&Request::new(())));
}

#[test]
fn does_not_require_response_payload_inspection_by_default() {
    let rules = FirewallHttpRules(Arc::from([DummyRule {
        requires_payload_inspection: false,
    }
    .into_dyn()]));

    assert!(!rules.has_http_response_payload_inspection_match(&Request::new(())));
}

#[test]
fn response_matcher_can_disable_response_payload_inspection() {
    #[derive(Debug)]
    struct ResponseRule;

    impl Rule for ResponseRule {
        fn match_domain(&self, _: &Domain) -> bool {
            false
        }

        #[cfg(feature = "pac")]
        fn collect_pac_domains(&self, _: &mut crate::http::firewall::pac::PacScriptGenerator) {}

        fn match_http_response_payload_inspection_request(
            &self,
            _: crate::http::firewall::rule::HttpRequestMatcherView<'_>,
        ) -> bool {
            true
        }

        fn match_http_response_payload_inspection_response(
            &self,
            resp: crate::http::firewall::rule::HttpResponseMatcherView<'_>,
        ) -> bool {
            resp.status.is_success()
        }
    }

    let rules = FirewallHttpResponsePayloadInspectionRules(Arc::from([ResponseRule.into_dyn()]));

    assert!(rules.matches_http_response_payload_inspection(&Response::new(())));
    assert!(
        !rules.matches_http_response_payload_inspection(&StatusCode::NOT_FOUND.into_response())
    );
}

#[test]
fn response_payload_inspection_uses_union_across_matched_rules() {
    #[derive(Debug)]
    struct RequestOnlyRule;

    impl Rule for RequestOnlyRule {
        fn match_domain(&self, _: &Domain) -> bool {
            false
        }

        #[cfg(feature = "pac")]
        fn collect_pac_domains(&self, _: &mut crate::http::firewall::pac::PacScriptGenerator) {}

        fn match_http_response_payload_inspection_request(
            &self,
            _: crate::http::firewall::rule::HttpRequestMatcherView<'_>,
        ) -> bool {
            true
        }

        fn match_http_response_payload_inspection_response(
            &self,
            _: crate::http::firewall::rule::HttpResponseMatcherView<'_>,
        ) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct RequestAndResponseRule;

    impl Rule for RequestAndResponseRule {
        fn match_domain(&self, _: &Domain) -> bool {
            false
        }

        #[cfg(feature = "pac")]
        fn collect_pac_domains(&self, _: &mut crate::http::firewall::pac::PacScriptGenerator) {}

        fn match_http_response_payload_inspection_request(
            &self,
            _: crate::http::firewall::rule::HttpRequestMatcherView<'_>,
        ) -> bool {
            true
        }

        fn match_http_response_payload_inspection_response(
            &self,
            resp: crate::http::firewall::rule::HttpResponseMatcherView<'_>,
        ) -> bool {
            resp.status.is_success()
        }
    }

    let request_rules = FirewallHttpRules(Arc::from([
        RequestOnlyRule.into_dyn(),
        RequestAndResponseRule.into_dyn(),
    ]));

    let response_rules = request_rules
        .select_http_response_payload_inspection_rules(&Request::new(()))
        .expect("at least one rule should match request phase");

    assert!(response_rules.matches_http_response_payload_inspection(&Response::new(())));
    assert!(
        !response_rules
            .matches_http_response_payload_inspection(&StatusCode::NOT_FOUND.into_response())
    );
}
