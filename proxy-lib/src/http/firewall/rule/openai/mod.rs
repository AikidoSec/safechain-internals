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
        ws::handshake::mitm::{
            WebSocketRelayDirection, WebSocketRelayMessage, WebSocketRelayOutput,
        },
    },
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};
use serde::Deserialize;

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

const OPENAI_PROVIDER_KEY: ArcStr = arcstr!("openai");

/// Cap on how much of an HTTP request body we will buffer to extract the
/// model name. OpenAI requests can embed large contexts, but the top-level
/// `"model"` field is small and near the start. Oversized requests pass
/// through untouched.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(in crate::http::firewall) struct RuleOpenAi {
    target_domains: DomainMatcher,
    notifier: Option<EventNotifier>,
}

impl RuleOpenAi {
    pub(in crate::http::firewall) fn new(notifier: Option<EventNotifier>) -> Self {
        Self {
            target_domains: ["api.openai.com", "chatgpt.com", "*.chatgpt.com"]
                .into_iter()
                .collect(),
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
        // Inspect every WS handshake on matched OpenAI/ChatGPT domains for now
        info.req_headers.is_some()
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        // Strip permessage-deflate from any WS upgrade on matched OpenAI/ChatGPT
        // domains. Without this, rama's per-frame relay stays silent on the
        // resulting WebSocket and frames carrying `model` are invisible. The
        // remove is a no-op when the header isn't present (e.g. plain POSTs),
        // so this is safe to run unconditionally. Domain filtering already
        // happened in `match_domain`. See agent_knowledge/rama-ws-relay-issue.md.
        let mut req = req;
        if req
            .headers_mut()
            .remove("sec-websocket-extensions")
            .is_some()
        {
            tracing::debug!(
                path = req.uri().path(),
                "openai: stripped sec-websocket-extensions on WS upgrade"
            );
        }

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
            .context("collect openai request body")?
            .to_bytes();

        if bytes.len() > MAX_BODY_BYTES {
            tracing::debug!(
                body_size = bytes.len(),
                "openai request body exceeds cap, skipping ai-usage detection"
            );
            return Ok(RequestAction::Allow(Request::from_parts(
                parts,
                Body::from(bytes),
            )));
        }

        match parse_model_field(&bytes) {
            Some(model) => {
                tracing::debug!(model = %model, "openai request observed");
                if let Some(notifier) = self.notifier.as_ref() {
                    notifier.notify_ai_usage(AiUsageEvent {
                        ts_ms: SystemTimestampMilliseconds::now(),
                        provider: OPENAI_PROVIDER_KEY,
                        model,
                    });
                }
            }
            None => {
                tracing::debug!(
                    path = parts.uri.path(),
                    body_size = bytes.len(),
                    body = %String::from_utf8_lossy(&bytes),
                    "openai: request body did not yield a model"
                );
            }
        }

        Ok(RequestAction::Allow(Request::from_parts(
            parts,
            Body::from(bytes),
        )))
    }

    async fn evaluate_ws_relay_msg(
        &self,
        dir: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Result<WebSocketRelayOutput, BoxError> {
        // Only client→server frames carry the user's model selection.
        if dir == WebSocketRelayDirection::Egress
            && let Some(notifier) = self.notifier.as_ref()
        {
            for msg in &data.messages {
                if let WebSocketRelayMessage::Text(utf8_bytes) = msg
                    && let Some(model) = parse_model_field(utf8_bytes.as_str().as_bytes())
                {
                    tracing::debug!(model = %model, "openai ws frame observed");
                    notifier.notify_ai_usage(AiUsageEvent {
                        ts_ms: SystemTimestampMilliseconds::now(),
                        provider: OPENAI_PROVIDER_KEY,
                        model,
                    });
                }
            }
        }
        Ok(data)
    }
}

/// HTTP endpoints whose request body carries a top-level `model` field.
fn path_carries_model(path: &str) -> bool {
    matches!(
        path,
        "/v1/responses"
            | "/v1/responses/compact"
            | "/v1/chat/completions"
            | "/v1/completions"
            | "/v1/embeddings"
            | "/v1/moderations"
            | "/backend-api/codex/responses"
    )
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
