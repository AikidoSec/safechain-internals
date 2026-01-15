use rama::{
    Layer, Service,
    error::{BoxError, OpaqueError},
    extensions::ExtensionsMut as _,
    http::{Request, Response},
    telemetry::tracing,
};

use crate::firewall::Firewall;

#[derive(Debug, Clone)]
pub struct EvaluateResponseService<S> {
    inner: S,
    firewall: Firewall,
}

#[derive(Debug, Clone)]
pub(crate) struct ResponseRequestDomain(pub rama::net::address::Domain);

#[derive(Debug, Clone)]
/// Created using [`Firewall::into_evaluate_response_layer`].
pub struct EvaluateResponseLayer(pub(in crate::firewall) Firewall);

impl<S> Service<Request> for EvaluateResponseService<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = OpaqueError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let request_domain = crate::http::try_get_domain_for_req(&req).map(|d| d.into_owned());

        let mut resp = self
            .inner
            .serve(req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;

        if let Some(domain) = request_domain {
            resp.extensions_mut().insert(ResponseRequestDomain(domain));
        }

        tracing::trace!("EvaluateResponseService: evaluating response");
        self.firewall.evaluate_response(resp).await
    }
}

impl<S> Layer<S> for EvaluateResponseLayer {
    type Service = EvaluateResponseService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EvaluateResponseService {
            inner,
            firewall: self.0.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        EvaluateResponseService {
            inner,
            firewall: self.0,
        }
    }
}
