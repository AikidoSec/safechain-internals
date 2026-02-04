// Generate mock data such as fake requests for a product.

use std::{fmt, pin::Pin, sync::Arc};

use rama::{error::OpaqueError, http::Request};
use tokio::sync::Mutex;

pub mod pypi;
pub mod random;
pub mod vscode;

#[derive(Debug)]
pub struct MockRequestParameters {
    pub malware_ratio: f64,
}

impl Default for MockRequestParameters {
    fn default() -> Self {
        Self { malware_ratio: 0.1 }
    }
}

pub trait RequestMocker: fmt::Debug + Sized + Send + Sync + 'static {
    fn mock_request(
        &mut self,
        params: MockRequestParameters,
    ) -> impl Future<Output = Result<Request, OpaqueError>> + Send + '_;

    /// Converts this [`RequestMocker`] into a [`DynRequestMocker`] trait object.
    fn into_dyn(self) -> BoxRequestMocker {
        BoxRequestMocker(Arc::new(Mutex::new(self)))
    }
}

#[derive(Debug, Clone)]
pub struct BoxRequestMocker(Arc<Mutex<dyn DynRequestMocker + Send + Sync + 'static>>);

impl RequestMocker for BoxRequestMocker {
    #[inline(always)]
    async fn mock_request(
        &mut self,
        params: MockRequestParameters,
    ) -> Result<Request, OpaqueError> {
        self.0.lock().await.dyn_mock_request(params).await
    }

    fn into_dyn(self) -> BoxRequestMocker {
        self.clone()
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
#[allow(clippy::type_complexity)]
pub trait DynRequestMocker: fmt::Debug {
    fn dyn_mock_request(
        &mut self,
        params: MockRequestParameters,
    ) -> Pin<Box<dyn Future<Output = Result<Request, OpaqueError>> + Send + '_>>;
}

impl<M: RequestMocker + fmt::Debug> DynRequestMocker for M {
    #[inline(always)]
    /// see [`RequestMocker::mock_request`] for more information.
    fn dyn_mock_request(
        &mut self,
        params: MockRequestParameters,
    ) -> Pin<Box<dyn Future<Output = Result<Request, OpaqueError>> + Send + '_>> {
        Box::pin(self.mock_request(params))
    }
}
