// Generate mock data such as fake requests for a product.

use rama::http::Request;

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

pub trait RequestMocker: Send + Sync + 'static {
    /// The type of error returned by the request mocker.
    type Error: Send + 'static;

    fn mock_request(
        &mut self,
        params: MockRequestParameters,
    ) -> impl Future<Output = Result<Request, Self::Error>> + Send + '_;
}
