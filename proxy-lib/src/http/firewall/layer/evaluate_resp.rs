use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    http::{Request, Response},
    telemetry::tracing,
};

use crate::http::firewall::Firewall;

#[derive(Debug, Clone)]
pub struct EvaluateResponseService<S> {
    inner: S,
    firewall: Firewall,
}

#[derive(Debug, Clone)]
/// Created using [`Firewall::into_evaluate_response_layer`].
pub struct EvaluateResponseLayer(pub(in crate::http::firewall) Firewall);

impl<S> Service<Request> for EvaluateResponseService<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let resp = self.inner.serve(req).await.into_box_error()?;

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
