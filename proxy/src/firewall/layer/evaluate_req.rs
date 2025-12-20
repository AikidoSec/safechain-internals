use rama::{
    Layer, Service,
    error::{BoxError, OpaqueError},
    http::{Request, Response},
    telemetry::tracing,
};

use crate::firewall::{Firewall, rule::RequestAction};

#[derive(Debug, Clone)]
pub struct EvaluateRequestService<S> {
    inner: S,
    firewall: Firewall,
}

#[derive(Debug, Clone)]
/// Created using [`Firewall::into_evaluate_request_layer`].
pub struct EvaluateRequestLayer(pub(in crate::firewall) Firewall);

impl<S> Service<Request> for EvaluateRequestService<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = OpaqueError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        match self.firewall.evaluate_request(req).await? {
            RequestAction::Allow(req) => self
                .inner
                .serve(req)
                .await
                .map_err(|err| OpaqueError::from_boxed(err.into())),
            RequestAction::Block(resp) => {
                tracing::trace!(
                    "EvaluateRequestService: firewall blocked reuqest with self-generated response"
                );
                Ok(resp)
            }
        }
    }
}

impl<S> Layer<S> for EvaluateRequestLayer {
    type Service = EvaluateRequestService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EvaluateRequestService {
            inner,
            firewall: self.0.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        EvaluateRequestService {
            inner,
            firewall: self.0,
        }
    }
}
