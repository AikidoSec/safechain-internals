use std::{pin::Pin, sync::Arc};

use rama::{error::OpaqueError, http::Request, net::address::Domain};

pub mod chrome;
pub mod vscode;

// NOTE: anything can implement this rule,
// including if we wish in future a dynamic Scriptable version,
// e.g. using rama-roto, to ensure any roto script that provides
// these functions is able to block.
//
// For now all implementations are in Rust, to keep it easy.

pub trait BlockRule: Sized + Send + Sync + 'static {
    fn product_name(&self) -> &'static str;

    fn match_domain(&self, domain: &Domain) -> bool;

    fn block_request(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_;

    fn into_dyn(self) -> DynBlockRule {
        DynBlockRule {
            inner: Arc::new(self),
        }
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
#[allow(clippy::type_complexity)]
trait DynBlockRuleInner {
    fn dyn_product_name(&self) -> &'static str;

    fn dyn_block_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_>>;

    fn dyn_match_domain(&self, domain: &Domain) -> bool;
}

impl<R: BlockRule> DynBlockRuleInner for R {
    #[inline(always)]
    fn dyn_product_name(&self) -> &'static str {
        self.product_name()
    }

    #[inline(always)]
    fn dyn_block_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_>> {
        Box::pin(self.block_request(req))
    }

    #[inline(always)]
    fn dyn_match_domain(&self, domain: &Domain) -> bool {
        self.match_domain(domain)
    }
}

/// A dyn-patched [`BlockRule`].
pub struct DynBlockRule {
    inner: Arc<dyn DynBlockRuleInner + Send + Sync + 'static>,
}

impl Clone for DynBlockRule {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Debug for DynBlockRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynBlockRule").finish()
    }
}

impl BlockRule for DynBlockRule {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        self.inner.dyn_product_name()
    }

    #[inline(always)]
    fn block_request(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_ {
        self.inner.dyn_block_request(req)
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.inner.dyn_match_domain(domain)
    }

    #[inline(always)]
    fn into_dyn(self) -> Self {
        self
    }
}
