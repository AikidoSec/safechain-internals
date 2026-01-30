use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::{Body, Request, Uri},
};

use rand::{rng, seq::IndexedRandom as _};

use safechain_proxy_lib::firewall::malware_list::MALWARE_LIST_URI_STR_PYPI;

use crate::mock::{MockRequestParameters, RequestMocker};

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct RandomMocker;

impl RandomMocker {
    pub fn new() -> Self {
        Self
    }
}

impl RequestMocker for RandomMocker {
    type Error = OpaqueError;

    async fn mock_request(
        &mut self,
        _params: MockRequestParameters,
    ) -> Result<Request, Self::Error> {
        let uri = random_uri()?;

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = uri;
        Ok(req)
    }
}

fn random_uri() -> Result<Uri, OpaqueError> {
    Ok(Uri::from_static(
        [
            "http://example.com",
            "https://example.com",
            "https://aikido.dev",
            MALWARE_LIST_URI_STR_PYPI,
            "https://http-test.ramaproxy.org/method",
            "https://http-test.ramaproxy.org/response-stream",
            "https://http-test.ramaproxy.org/response-compression",
        ]
        .choose(&mut rng())
        .context("select random None uri")?,
    ))
}
