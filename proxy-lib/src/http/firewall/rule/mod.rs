use std::{pin::Pin, sync::Arc};

use rama::{
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    http::{
        Method, Request, Response, StatusCode, Uri, Version,
        header::{HeaderMap, HeaderValue},
        request,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayOutput},
    },
    net::address::Domain,
    telemetry::tracing,
};

use super::events::{Artifact, BlockReason, BlockedEventInfo};
use crate::endpoint_protection::PackagePolicyDecision;
use crate::http::response::generate_blocked_response_for_req;

pub struct BlockedRequest {
    pub response: Response,
    pub info: BlockedEventInfo,
    pub suppress_notification: bool,
}

impl BlockedRequest {
    pub(crate) fn blocked(req: Request, artifact: Artifact, reason: BlockReason) -> Self {
        Self {
            response: generate_blocked_response_for_req(req, &reason),
            info: BlockedEventInfo {
                artifact,
                block_reason: reason,
            },
            suppress_notification: false,
        }
    }

    pub(crate) fn with_suppressed_notification(mut self) -> Self {
        self.suppress_notification = true;
        self
    }
}

/// Maps a PackagePolicyDecision to the corresponding BlockReason.
pub(crate) fn block_reason_for(decision: PackagePolicyDecision) -> BlockReason {
    match decision {
        PackagePolicyDecision::Rejected => BlockReason::Rejected,
        PackagePolicyDecision::BlockAll => BlockReason::BlockAll,
        PackagePolicyDecision::RequestInstall => BlockReason::RequestInstall,
        PackagePolicyDecision::Allow | PackagePolicyDecision::Defer => {
            unreachable!("Allow and Defer are not blocking decisions")
        }
    }
}

#[cfg(feature = "pac")]
pub use super::pac::PacScriptGenerator;

pub mod hijack;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod open_vsx;
pub mod pypi;
pub mod skills_sh;
pub mod vscode;

#[cfg_attr(
    not(any(not(feature = "apple-networkextension"), feature = "test-utils", test)),
    expect(unused)
)]
pub mod chrome;

/// Action determined by a [`Rule`] when evaluating an http [`Request`]
/// in its [`Rule::evaluate_request`] request.
pub enum RequestAction {
    /// Allow a [`Request`] to proceed to the next [`Rule`] or egress server,
    /// (e.g. the application server, such as an extension CDN)
    ///
    /// A [`Request`] is sent to the egress (destination) server _only_
    /// if the _all_ [`Rule`]s [`RequestAction::Allow`] it.
    ///
    /// It is possible that the [`Rule`] modified the [`Request`].
    Allow(Request),
    /// Block the [`Request`] from proceeding to the next [`Rule`] or egress server.
    ///
    /// A [`BlockedRequest`] contains both the http [`Response`] to return to the ingress client
    /// (e.g. the application wishing to download an extension) and [`BlockedEventInfo`] metadata
    /// about what was blocked.
    Block(BlockedRequest),
}

// NOTE: anything can implement this rule,
// including if we wish in future a dynamic Scriptable version,
// e.g. using rama-roto, to ensure any roto script that provides
// these functions is able to block.
//
// For now all implementations are in Rust, to keep it easy.

#[derive(Debug, Clone, Copy)]
pub struct WebSocketHandshakeInfo<'a> {
    /// Target domain selected for the WebSocket's parent connection.
    pub domain: Option<&'a Domain>,
    /// App source bundle id from which the traffic originated
    pub app_source_bundle_id: Option<&'a str>,
    /// Parsed HTTP request metadata for the upgrade handshake.
    pub req_headers: Option<&'a request::Parts>,
}

#[derive(Debug, Clone, Copy)]
pub struct HttpRequestMatcherView<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub version: Version,
    pub headers: &'a HeaderMap<HeaderValue>,
    pub extensions: &'a Extensions,
}

impl<'a> HttpRequestMatcherView<'a> {
    pub fn new<Body>(req: &'a Request<Body>) -> Self {
        Self {
            method: req.method(),
            uri: req.uri(),
            version: req.version(),
            headers: req.headers(),
            extensions: req.extensions(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpResponseMatcherView<'a> {
    pub status: StatusCode,
    pub version: Version,
    pub headers: &'a HeaderMap<HeaderValue>,
    pub extensions: &'a Extensions,
}

impl<'a> HttpResponseMatcherView<'a> {
    pub fn new<Body>(resp: &'a Response<Body>) -> Self {
        Self {
            status: resp.status(),
            version: resp.version(),
            headers: resp.headers(),
            extensions: resp.extensions(),
        }
    }
}

/// A trait defining how the [`Firewall`] inspects, modifies, or blocks HTTP traffic.
///
/// A [`Rule`] serves two primary purposes:
/// 1. **Traffic Filtering**: Identifying which [`Domain`]s should be intercepted
///    (Man-In-The-Middle, or MITM in short).
/// 2. **Traffic Manipulation**: Inspecting and potentially altering [`Request`]s and [`Response`]s.
///
/// ### MITM and PAC Integration
///
/// To optimize performance, the [`Firewall`] only performs Man-In-The-Middle (MITM) operations on
/// traffic that matches at least one [`Rule`]. This is managed in two ways:
///
/// - **Active Inspection**: For incoming traffic already hitting the proxy.
/// - **PAC Generation**: Via a Proxy Auto-Configuration (PAC) file, allowing the browser to
///   determine if traffic should bypass the proxy entirely or be routed through it.
///
/// For more details on PAC, see `docs/proxy/pac.md`.
///
/// [`Firewall`]: super::Firewall
pub trait Rule: Sized + Send + Sync + 'static {
    /// Determines if this [`Rule`] should trigger MITM inspection for a given [`Domain`].
    ///
    /// The [`Firewall`] aggregates the results of all rules to decide whether to
    /// decrypt and inspect a connection or let it pass through as opaque TCP traffic.
    ///
    /// [`Firewall`]: super::Firewall
    fn match_domain(&self, domain: &Domain) -> bool;

    /// Request-time matcher for response payload inspection.
    ///
    /// Rules should usually match on request metadata such as URI or headers here.
    /// If this matches, Rama will evaluate the response-time matcher before deciding
    /// whether to decompress the response body.
    fn match_http_response_payload_inspection_request(
        &self,
        _req: HttpRequestMatcherView<'_>,
    ) -> bool {
        false
    }

    /// Response-time matcher for response payload inspection.
    ///
    /// This is only evaluated when
    /// [`Rule::match_http_response_payload_inspection_request`] matched earlier.
    /// The default implementation returns `true` as most rules will only
    /// know enough with request alone.
    fn match_http_response_payload_inspection_response(
        &self,
        _resp: HttpResponseMatcherView<'_>,
    ) -> bool {
        true
    }

    /// Determines if this [`Rule`] should inspect a WebSocket upgrade for a given handshake.
    ///
    /// The default implementation matches no WS handshake. Implement this method
    /// only in case you want to intercept some or all WS traffic
    /// for the matched (http(s)) domains.
    ///
    /// This hook is evaluated before the proxy enters WebSocket MITM relay mode.
    /// A rule can use the target domain and upgrade request headers to decide whether
    /// it wants to observe or rewrite the WebSocket message stream.
    ///
    /// Returning `true` means the connection should be relayed through the WebSocket
    /// MITM path so [`Rule::evaluate_ws_relay_msg`] can inspect frames.
    ///
    /// [`Firewall`]: super::Firewall
    fn match_ws_handshake<'a>(&self, info: WebSocketHandshakeInfo<'a>) -> bool {
        tracing::debug!(
            app_source_bundle_id = ?info.app_source_bundle_id,
            domain = ?info.domain,
            path = info.req_headers.as_ref().map(|p| p.uri.path()),
            "WS handshake not matched (default impl)",
        );
        false
    }

    #[cfg(feature = "pac")]
    /// Contributes domains to the Proxy Auto-Configuration (PAC) script generation.
    ///
    /// Unlike [`Rule::match_domain`], which acts on traffic that has already reached the proxy,
    /// this method helps generate the PAC file used by clients to decide *if* they should
    /// connect to the proxy at all.
    ///
    /// **Behavioral Expectation:**
    /// Typically, any domain returning `true` in `match_domain` should also be added to
    /// the PAC script via [`PacScriptGenerator::write_domain`].
    ///
    /// - **PAC Flow**: Domains not in the PAC script bypass the proxy, improving performance.
    /// - **Standard Flow**: If the proxy is a global system proxy, all traffic arrives here;
    ///   `match_domain` then decides whether to decrypt (MITM) or simply tunnel the traffic.
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator);

    /// Evaluates an incoming intercepted [`Request`].
    ///
    /// Returns a [`RequestAction`] indicating if the request should be forwarded,
    /// modified, or blocked with a custom response.
    ///
    /// The default implementation evaluates to allow _any_ request.
    /// Implements this if you wish custom behaviour, such as HTTP request
    /// inspection, modification or the ability to return a block response early.
    ///
    /// ### Errors
    ///
    /// Return an error only for unrecoverable failures where the underlying TCP connection
    /// must be dropped immediately. For standard logic (like blocking a site),
    /// return a [`RequestAction`] instead.
    ///
    /// ### Logic Flow
    ///
    /// ```text
    /// [Client] ----> [Request] ----> [Rule (Proxy)] ----> [Server]
    ///                                     |
    ///                                     └──> Can Modify or Block
    /// ```
    fn evaluate_request(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<RequestAction, BoxError>> + Send + '_ {
        std::future::ready(Ok(RequestAction::Allow(req)))
    }

    /// Evaluates the [`Response`] received from the server before it reaches the client.
    ///
    /// The default implementation evaluates to allow _any_ response.
    /// Implements this if you wish custom behaviour, such as HTTP response
    /// inspection, modification or total replacement.
    ///
    /// This allows the rule to:
    /// - Pass the response through untouched.
    /// - Modify headers or body content.
    /// - Replace the response entirely (e.g., injecting a block page).
    ///
    /// ### Errors
    /// Return an error only to abort the flow and close the connection. Otherwise,
    /// return a modified or custom [`Response`].
    ///
    /// ### Logic Flow
    /// ```text
    /// [Client] <---- [Response] <---- [Rule (Proxy)] <---- [Server]
    ///                                      |
    ///                                      └──> Can Modify or Replace
    /// ```
    fn evaluate_response(
        &self,
        resp: Response,
    ) -> impl Future<Output = Result<Response, BoxError>> + Send + '_ {
        std::future::ready(Ok(resp))
    }

    /// Evaluates WebSocket relay message(s), in either direction.
    ///
    /// The default implementation evaluates to allow _any_ msg.
    /// Implements this if you wish custom behaviour, such as WS message
    /// inspection, modification, or dropping of messages.
    fn evaluate_ws_relay_msg(
        &self,
        _: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> impl Future<Output = Result<WebSocketRelayOutput, BoxError>> + Send + '_ {
        std::future::ready(Ok(data))
    }

    /// Converts this [`Rule`] into a [`DynRule`] trait object.
    ///
    /// This allows the [`Firewall`] to store a collection of heterogeneous rules.
    /// See the [Rust Book](https://doc.rust-lang.org/book/ch17-02-trait-objects.html)
    /// for more information on trait objects.
    ///
    /// [`Firewall`]: super::Firewall
    fn into_dyn(self) -> DynRule {
        DynRule {
            inner: Arc::new(self),
        }
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
#[allow(clippy::type_complexity)]
trait DynRuleInner {
    fn dyn_evaluate_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<RequestAction, BoxError>> + Send + '_>>;

    fn dyn_evaluate_response(
        &self,
        resp: Response,
    ) -> Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send + '_>>;

    fn dyn_match_domain(&self, domain: &Domain) -> bool;

    fn dyn_match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool;

    fn dyn_match_http_response_payload_inspection_response(
        &self,
        resp: HttpResponseMatcherView<'_>,
    ) -> bool;

    fn dyn_match_ws_handshake<'a>(&self, info: WebSocketHandshakeInfo<'a>) -> bool;

    fn dyn_evaluate_ws_relay_msg(
        &self,
        dir: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Pin<Box<dyn Future<Output = Result<WebSocketRelayOutput, BoxError>> + Send + '_>>;

    #[cfg(feature = "pac")]
    fn dyn_collect_pac_domains(&self, generator: &mut PacScriptGenerator);
}

#[warn(clippy::missing_trait_methods)]
impl<R: Rule> DynRuleInner for R {
    #[inline(always)]
    /// see [`Rule::evaluate_request`] for more information.
    fn dyn_evaluate_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<RequestAction, BoxError>> + Send + '_>> {
        Box::pin(self.evaluate_request(req))
    }

    #[inline(always)]
    /// see [`Rule::evaluate_response`] for more information.
    fn dyn_evaluate_response(
        &self,
        resp: Response,
    ) -> Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send + '_>> {
        Box::pin(self.evaluate_response(resp))
    }

    #[inline(always)]
    fn dyn_evaluate_ws_relay_msg(
        &self,
        dir: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Pin<Box<dyn Future<Output = Result<WebSocketRelayOutput, BoxError>> + Send + '_>> {
        Box::pin(self.evaluate_ws_relay_msg(dir, data))
    }

    #[inline(always)]
    /// see [`Rule::match_domain`] for more information.
    fn dyn_match_domain(&self, domain: &Domain) -> bool {
        self.match_domain(domain)
    }

    #[inline(always)]
    /// see [`Rule::match_http_response_payload_inspection_request`] for more information.
    fn dyn_match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool {
        self.match_http_response_payload_inspection_request(req)
    }

    #[inline(always)]
    /// see [`Rule::match_http_response_payload_inspection_response`] for more information.
    fn dyn_match_http_response_payload_inspection_response(
        &self,
        resp: HttpResponseMatcherView<'_>,
    ) -> bool {
        self.match_http_response_payload_inspection_response(resp)
    }

    #[inline(always)]
    /// see [`Rule::match_domain`] for more information.
    fn dyn_match_ws_handshake<'a>(&self, info: WebSocketHandshakeInfo<'a>) -> bool {
        self.match_ws_handshake(info)
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    /// see [`Rule::collect_pac_domains`] for more information.
    fn dyn_collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        self.collect_pac_domains(generator);
    }
}

/// A dyn-patched [`Rule`] (a "trait object" version of a [`Rule`]).
///
/// See <https://doc.rust-lang.org/1.8.0/book/trait-objects.html> for more information
/// about "trait objects".
///
/// Exclusively created using [`Rule::into_dyn`].
pub struct DynRule {
    inner: Arc<dyn DynRuleInner + Send + Sync + 'static>,
}

impl Clone for DynRule {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Debug for DynRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynRule").finish()
    }
}

#[warn(clippy::missing_trait_methods)]
impl Rule for DynRule {
    #[inline(always)]
    fn evaluate_request(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<RequestAction, BoxError>> + Send + '_ {
        self.inner.dyn_evaluate_request(req)
    }

    #[inline(always)]
    fn evaluate_response(
        &self,
        resp: Response,
    ) -> impl Future<Output = Result<Response, BoxError>> + Send + '_ {
        self.inner.dyn_evaluate_response(resp)
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.inner.dyn_match_domain(domain)
    }

    #[inline(always)]
    fn match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool {
        self.inner
            .dyn_match_http_response_payload_inspection_request(req)
    }

    #[inline(always)]
    fn match_http_response_payload_inspection_response(
        &self,
        resp: HttpResponseMatcherView<'_>,
    ) -> bool {
        self.inner
            .dyn_match_http_response_payload_inspection_response(resp)
    }

    #[inline(always)]
    fn match_ws_handshake<'a>(&self, info: WebSocketHandshakeInfo<'a>) -> bool {
        self.inner.dyn_match_ws_handshake(info)
    }

    #[inline(always)]
    fn evaluate_ws_relay_msg(
        &self,
        dir: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> impl Future<Output = Result<WebSocketRelayOutput, BoxError>> + Send + '_ {
        self.inner.dyn_evaluate_ws_relay_msg(dir, data)
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        self.inner.dyn_collect_pac_domains(generator);
    }

    #[inline(always)]
    fn into_dyn(self) -> Self {
        self
    }
}
