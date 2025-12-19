use std::borrow::Cow;

use rama::{
    Layer as _, Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::{ExtensionsMut as _, ExtensionsRef as _},
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        headers::{self, Accept, HeaderMapExt},
        layer::{
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
        },
        mime,
        service::web::response::{Headers, Html, IntoResponse as _},
    },
    net::{
        address::DomainTrie,
        proxy::ProxyTarget,
        tls::{SecureTransport, client::ClientConfig},
    },
    telemetry::tracing,
    tls::boring::client::TlsConnectorDataBuilder,
};

use crate::firewall::{
    BLOCK_DOMAINS_CHROME, BLOCK_DOMAINS_VSCODE, BlockRule as _, DynBlockRule,
    chrome::BlockRuleChrome, vscode::BlockRuleVSCode,
};

#[derive(Debug, Clone)]
pub(super) struct HttpClient<S> {
    inner: S,
    block_rules: DomainTrie<DynBlockRule>,
}

pub(super) fn new_https_client()
-> Result<HttpClient<impl Service<Request, Output = Response, Error = OpaqueError>>, OpaqueError> {
    let inner = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        MapResponseBodyLayer::new(Body::new),
        DecompressionLayer::new(),
    )
        .into_layer(
            EasyHttpWebClient::connector_builder()
                .with_default_transport_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
                .with_tls_support_using_boringssl(None)
                .with_default_http_connector()
                .try_with_default_connection_pool()
                .context("create connection pool for proxy web client")?
                .build_client(),
        );

    // TODO: this should be managed to allow updates and other
    // dynamic featurues (in future)

    let mut block_rules = DomainTrie::new();

    let vscode_rule = BlockRuleVSCode::new().into_dyn();
    for domain in BLOCK_DOMAINS_VSCODE {
        block_rules.insert_domain(domain, vscode_rule.clone());
    }

    let chrome_rule = BlockRuleChrome::new().into_dyn();
    for domain in BLOCK_DOMAINS_CHROME {
        block_rules.insert_domain(domain, chrome_rule.clone());
    }

    Ok(HttpClient { inner, block_rules })
}

impl<S> Service<Request> for HttpClient<S>
where
    S: Service<Request, Output = Response, Error = OpaqueError>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();
        tracing::debug!(uri = %uri, "serving http(s) over proxy (egress) client");

        let maybe_domain = match req.extensions().get() {
            Some(ProxyTarget(target)) => target.host.as_domain().map(Cow::Borrowed),
            // missing proxy target possible in case of http plain text proxy req
            None => req
                .uri()
                .host()
                .and_then(|h| h.parse().ok().map(Cow::Owned)),
        };

        if let Some(domain) = maybe_domain.as_deref()
            && let Some(m) = self.block_rules.match_parent(domain)
        {
            let maybe_detected_ct = req.headers().typed_get().and_then(|Accept(qvs)| {
                qvs.iter().find_map(|qv| {
                    let r#type = qv.value.subtype();
                    if r#type == mime::JSON {
                        Some(ContentType::Json)
                    } else if r#type == mime::HTML {
                        Some(ContentType::Html)
                    } else if r#type == mime::TEXT {
                        Some(ContentType::Txt)
                    } else if r#type == mime::XML {
                        Some(ContentType::Xml)
                    } else {
                        None
                    }
                })
            });

            match m.value.block_request(req).await? {
                Some(r) => req = r,
                None => {
                    return Ok(generate_blocked_response(maybe_detected_ct));
                }
            }
        }

        if let Some(ch) = req
            .extensions()
            .get::<SecureTransport>()
            .and_then(|st| st.client_hello())
            .cloned()
        {
            match TlsConnectorDataBuilder::try_from(&ClientConfig::from(ch)) {
                Ok(mirror_tls_cfg) => {
                    tracing::trace!(
                        "inject TLS Connector data builder based on input TLS ClientHello"
                    );
                    req.extensions_mut().insert(mirror_tls_cfg);
                }
                Err(err) => {
                    tracing::debug!(
                        "failed to create TLS Connector data builder based on input TLS ClientHello: err = {err}; proceed anyway with default rama boring CH"
                    );
                }
            }
        }

        match self.inner.serve(req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                tracing::error!(uri = %uri, "error forwarding request: {err:?}");
                let resp = StatusCode::BAD_GATEWAY.into_response();
                Ok(resp)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Content Type detected so we can return appropriate msg.
enum ContentType {
    Html,
    Txt,
    Json,
    Xml,
}

fn generate_blocked_response(maybe_detected_ct: Option<ContentType>) -> Response {
    match maybe_detected_ct {
        Some(ContentType::Html) => (
            StatusCode::FORBIDDEN,
            Html(
                r##"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Blocked</title>
</head>
<body>
    <h1>Request blocked</h1>
    <p>The requested source was blocked due to your organization policy.</p>
    <p>Contact your security administrator for more information.</p>
</body>
</html>
"##,
            ),
        )
            .into_response(),
        Some(ContentType::Txt) => (
            StatusCode::FORBIDDEN,
            r##"The requested source was blocked due to your organization policy.
Contact your security administrator for more information.
"##,
        )
            .into_response(),
        Some(ContentType::Json) => (
            StatusCode::FORBIDDEN,
            Headers::single(headers::ContentType::json()),
            r##"{
    "error": "blocked",
    "message": "The requested source was blocked due to your organization policy.",
    "action": "Contact your security administrator for more information."
}"##,
        )
            .into_response(),
        Some(ContentType::Xml) => (
            StatusCode::FORBIDDEN,
            Headers::single(headers::ContentType::json()),
            r##"<?xml version="1.0" encoding="UTF-8"?>
<response>
    <error>blocked</error>
    <message>The requested source was blocked due to your organization policy.</message>
    <action>Contact your security administrator for more information.</action>
</response>"##,
        )
            .into_response(),
        None => StatusCode::FORBIDDEN.into_response(),
    }
}
