use std::fmt;

use crate::{
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::AiUsageEvent,
        notifier::EventNotifier,
        rule::Rule,
    },
    utils::time::SystemTimestampMilliseconds,
};
use rama::{
    error::BoxError,
    http::ws::handshake::mitm::{
        WebSocketRelayDirection, WebSocketRelayMessage, WebSocketRelayOutput,
    },
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};
use serde::Deserialize;

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

const OPENAI_PROVIDER_KEY: ArcStr = arcstr!("openai");

pub(in crate::http::firewall) struct RuleOpenAi {
    target_domains: DomainMatcher,
    notifier: Option<EventNotifier>,
}

impl RuleOpenAi {
    pub(in crate::http::firewall) fn new(notifier: Option<EventNotifier>) -> Self {
        Self {
            target_domains: ["chatgpt.com"].into_iter().collect(),
            notifier,
        }
    }
}

impl fmt::Debug for RuleOpenAi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleOpenAi").finish()
    }
}

impl Rule for RuleOpenAi {
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

    fn match_ws_handshake<'a>(&self, info: super::WebSocketHandshakeInfo<'a>) -> bool {
        info.req_headers
            .map(|parts| parts.uri.path() == "/backend-api/codex/responses")
            .unwrap_or(false)
    }

    async fn evaluate_ws_relay_msg(
        &self,
        dir: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Result<WebSocketRelayOutput, BoxError> {
        // client→server
        if dir != WebSocketRelayDirection::Ingress {
            return Ok(data);
        }

        for msg in &data.messages {
            let WebSocketRelayMessage::Text(utf8_bytes) = msg else {
                continue;
            };
            let body_bytes = utf8_bytes.as_str().as_bytes();
            match parse_model_field(body_bytes) {
                Some(model) => self.observe_model(model),
                None => log_unparseable_frame(body_bytes),
            }
        }
        Ok(data)
    }
}

impl RuleOpenAi {
    fn observe_model(&self, model: ArcStr) {
        tracing::debug!(model = %model, "openai ws frame observed");
        if let Some(notifier) = self.notifier.as_ref() {
            notifier.notify_ai_usage(AiUsageEvent {
                ts_ms: SystemTimestampMilliseconds::now(),
                provider: OPENAI_PROVIDER_KEY,
                model,
            });
        }
    }
}

fn log_unparseable_frame(body_bytes: &[u8]) {
    let preview_len = body_bytes.len().min(2048);
    tracing::debug!(
        size = body_bytes.len(),
        preview = %String::from_utf8_lossy(&body_bytes[..preview_len]),
        "openai ws ingress frame: no model"
    );
}

#[derive(Debug, Deserialize)]
struct OpenAiRequestModel {
    model: ArcStr,
}

fn parse_model_field(bytes: &[u8]) -> Option<ArcStr> {
    let parsed: OpenAiRequestModel = serde_json::from_slice(bytes).ok()?;
    let trimmed = parsed.model.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.len() == parsed.model.len() {
        Some(parsed.model)
    } else {
        Some(ArcStr::from(trimmed))
    }
}

#[cfg(test)]
mod tests;
