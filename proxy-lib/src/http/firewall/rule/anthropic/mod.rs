use std::fmt;

use crate::{
    http::{
        KnownContentType,
        firewall::{
            domain_matcher::DomainMatcher,
            events::AiUsageEvent,
            notifier::EventNotifier,
            rule::{RequestAction, Rule},
        },
    },
    utils::time::SystemTimestampMilliseconds,
};
use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Method, Request,
        body::util::BodyExt as _,
        headers::{ContentType, HeaderMapExt as _},
    },
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};
use serde::Deserialize;

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

const ANTHROPIC_PROVIDER_KEY: ArcStr = arcstr!("anthropic");

/// Cap on how much of the request body we will buffer to extract the model name.
/// Anthropic's prompts can include base64 images and long contexts, but the JSON
/// preamble carrying `"model": "..."` is small. Requests above this cap pass
/// through untouched (no event emitted).
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(in crate::http::firewall) struct RuleAnthropic {
    target_domains: DomainMatcher,
    notifier: Option<EventNotifier>,
}

impl RuleAnthropic {
    pub(in crate::http::firewall) fn new(notifier: Option<EventNotifier>) -> Self {
        Self {
            target_domains: ["api.anthropic.com"].into_iter().collect(),
            notifier,
        }
    }
}

impl fmt::Debug for RuleAnthropic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleAnthropic").finish()
    }
}

impl Rule for RuleAnthropic {
    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match(domain)
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        if req.method() != Method::POST {
            return Ok(RequestAction::Allow(req));
        }

        if !path_carries_model(req.uri().path()) {
            return Ok(RequestAction::Allow(req));
        }

        if req
            .headers()
            .typed_get::<ContentType>()
            .and_then(KnownContentType::detect_from_content_type_header)
            != Some(KnownContentType::Json)
        {
            return Ok(RequestAction::Allow(req));
        }

        let (parts, body) = req.into_parts();

        let bytes = body
            .collect()
            .await
            .context("collect anthropic request body")?
            .to_bytes();

        if bytes.len() > MAX_BODY_BYTES {
            tracing::debug!(
                body_size = bytes.len(),
                "anthropic request body exceeds cap, skipping ai-usage detection"
            );
            return Ok(RequestAction::Allow(Request::from_parts(
                parts,
                Body::from(bytes),
            )));
        }

        if let Some(model) = parse_model_field(&bytes) {
            tracing::debug!(model = %model, "anthropic request observed");
            if let Some(notifier) = self.notifier.as_ref() {
                notifier.notify_ai_usage(AiUsageEvent {
                    ts_ms: SystemTimestampMilliseconds::now(),
                    provider: ANTHROPIC_PROVIDER_KEY,
                    model,
                });
            }
        } else {
            tracing::debug!("anthropic request body did not contain a recognizable model field");
        }

        Ok(RequestAction::Allow(Request::from_parts(
            parts,
            Body::from(bytes),
        )))
    }
}

/// Endpoints whose request body carries a top-level `model` field.
fn path_carries_model(path: &str) -> bool {
    matches!(
        path,
        "/v1/messages" | "/v1/messages/count_tokens" | "/v1/complete"
    )
}

#[derive(Debug, Deserialize)]
struct AnthropicRequestModel {
    model: ArcStr,
}

fn parse_model_field(bytes: &[u8]) -> Option<ArcStr> {
    let parsed: AnthropicRequestModel = serde_json::from_slice(bytes)
        .inspect_err(|err| {
            tracing::debug!(
                error = %err,
                "failed to parse anthropic request body as JSON with `model`"
            );
        })
        .ok()?;
    let trimmed = parsed.model.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() == parsed.model.len() {
        Some(parsed.model)
    } else {
        Some(ArcStr::from(trimmed))
    }
}

#[cfg(test)]
mod tests;
