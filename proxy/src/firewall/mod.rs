use std::{pin::Pin, sync::Arc};

use rama::{error::OpaqueError, http::Request, net::address::Domain};

// NOTE:
//
// In the future we probably want these rules to be dynamic.
//
// - domain lists should probably be dynamic lists configured via a remote http service,
//   or via the local (Aikido) Agent
// - rules logic themselves should be dynamic, rama-roto could be used for that

pub mod chrome;
pub mod vscode;

pub const BLOCK_DOMAINS_VSCODE: &[Domain] = &[
    Domain::from_static("echo.ramaproxy.org"), // TODO: delete this test ramaproxy example :)
    Domain::from_static("gallery.vsassets.io"),
    Domain::from_static("gallerycdn.vsassets.io"),
];

pub const BLOCK_DOMAINS_CHROME: &[Domain] = &[Domain::from_static("clients2.google.com")];

pub trait BlockRule: Sized + Send + Sync + 'static {
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
trait DynBlockRuleInner {
    #[allow(clippy::type_complexity)]
    fn dyn_block_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_>>;
}

impl<R: BlockRule> DynBlockRuleInner for R {
    fn dyn_block_request(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_>> {
        Box::pin(self.block_request(req))
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
    fn block_request(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Option<Request>, OpaqueError>> + Send + '_ {
        self.inner.dyn_block_request(req)
    }

    #[inline]
    fn into_dyn(self) -> Self {
        self
    }
}
