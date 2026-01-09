use std::{pin::Pin, sync::Arc};

use rama::{
    error::OpaqueError,
    http::{Request, Response},
    net::address::Domain,
};

pub use super::pac::PacScriptGenerator;

pub mod chrome;
pub mod npm;
pub mod pypi;
pub mod vscode;

pub enum RequestAction {
    Allow(Request),
    Block(Response),
}

// NOTE: anything can implement this rule,
// including if we wish in future a dynamic Scriptable version,
// e.g. using rama-roto, to ensure any roto script that provides
// these functions is able to block.
//
// For now all implementations are in Rust, to keep it easy.

/// A firewall rule for a specific ecosystem/product.
///
/// Rules can influence proxy behaviour in three ways:
/// - Identify whether they apply to a request/response via [`Rule::match_domain`].
/// - Block or allow requests/responses via [`Rule::evaluate_request`] and [`Rule::evaluate_response`].
/// - Contribute domains to the generated PAC (Proxy Auto-Configuration) script via
///   [`Rule::collect_pac_domains`].
///
/// PAC is used to selectively route traffic through the proxy. For the full background and
/// operational details, see the proxy docs in `safechain-agent/docs/proxy.md`.
pub trait Rule: Sized + Send + Sync + 'static {
    fn product_name(&self) -> &'static str;

    fn match_domain(&self, domain: &Domain) -> bool;

    /// Write the domains this rule needs into the PAC (Proxy Auto-Configuration) script.
    ///
    /// The PAC script is used to ensure only relevant domains are routed through the proxy.
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator);

    fn evaluate_request(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<RequestAction, OpaqueError>> + Send + '_;

    fn evaluate_response(
        &self,
        resp: Response,
    ) -> impl Future<Output = Result<Response, OpaqueError>> + Send + '_;

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
    ) -> Pin<Box<dyn Future<Output = Result<RequestAction, OpaqueError>> + Send + '_>>;

    fn dyn_evaluate_response(
        &self,
        resp: Response,
    ) -> Pin<Box<dyn Future<Output = Result<Response, OpaqueError>> + Send + '_>>;

    fn dyn_match_domain(&self, domain: &Domain) -> bool;

    fn dyn_collect_pac_domains(&self, generator: &mut PacScriptGenerator);
}

impl<R: Rule> DynRuleInner for R {
    #[inline(always)]
    fn dyn_product_name(&self) -> &'static str {
        self.product_name()
    }

    #[inline(always)]
    fn dyn_evaluate_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<RequestAction, OpaqueError>> + Send + '_>> {
        Box::pin(self.evaluate_request(req))
    }

    #[inline(always)]
    fn dyn_evaluate_response(
        &self,
        resp: Response,
    ) -> Pin<Box<dyn Future<Output = Result<Response, OpaqueError>> + Send + '_>> {
        Box::pin(self.evaluate_response(resp))
    }

    #[inline(always)]
    fn dyn_match_domain(&self, domain: &Domain) -> bool {
        self.match_domain(domain)
    }

    #[inline(always)]
    fn dyn_collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        self.collect_pac_domains(generator);
    }
}

/// A dyn-patched [`Rule`].
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
    ) -> impl Future<Output = Result<RequestAction, OpaqueError>> + Send + '_ {
        self.inner.dyn_evaluate_request(req)
    }

    #[inline(always)]
    fn evaluate_response(
        &self,
        resp: Response,
    ) -> impl Future<Output = Result<Response, OpaqueError>> + Send + '_ {
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
