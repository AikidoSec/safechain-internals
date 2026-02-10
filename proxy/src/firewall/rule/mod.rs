use std::{pin::Pin, sync::Arc};

use rama::{
    error::BoxError,
    http::{Request, Response},
    net::address::Domain,
};

use super::events::BlockedEventInfo;

pub struct BlockedRequest {
    pub response: Response,
    pub info: BlockedEventInfo,
}

pub use super::pac::PacScriptGenerator;

pub mod chrome;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod pypi;
pub mod vscode;

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
    /// Returns a unique identifier or product name for this [`Rule`].
    ///
    /// This is currently used as an opaque identifier for logging and internal tracking.
    fn product_name(&self) -> &'static str;

    /// Determines if this [`Rule`] should trigger MITM inspection for a given [`Domain`].
    ///
    /// The [`Firewall`] aggregates the results of all rules to decide whether to
    /// decrypt and inspect a connection or let it pass through as opaque TCP traffic.
    ///
    /// [`Firewall`]: super::Firewall
    fn match_domain(&self, domain: &Domain) -> bool;

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
    ) -> impl Future<Output = Result<RequestAction, BoxError>> + Send + '_;

    /// Evaluates the [`Response`] received from the server before it reaches the client.
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
    ) -> impl Future<Output = Result<Response, BoxError>> + Send + '_;

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
    fn dyn_product_name(&self) -> &'static str;

    fn dyn_evaluate_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<RequestAction, BoxError>> + Send + '_>>;

    fn dyn_evaluate_response(
        &self,
        resp: Response,
    ) -> Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send + '_>>;

    fn dyn_match_domain(&self, domain: &Domain) -> bool;

    fn dyn_collect_pac_domains(&self, generator: &mut PacScriptGenerator);
}

impl<R: Rule> DynRuleInner for R {
    #[inline(always)]
    /// see [`Rule::product_name`] for more information.
    fn dyn_product_name(&self) -> &'static str {
        self.product_name()
    }

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
    /// see [`Rule::match_domain`] for more information.
    fn dyn_match_domain(&self, domain: &Domain) -> bool {
        self.match_domain(domain)
    }

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

impl Rule for DynRule {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        self.inner.dyn_product_name()
    }

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
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        self.inner.dyn_collect_pac_domains(generator);
    }

    #[inline(always)]
    fn into_dyn(self) -> Self {
        self
    }
}
