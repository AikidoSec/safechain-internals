use rama::{Layer, Service, error::BoxError, extensions::ExtensionsMut, io::Io};

#[derive(Debug, Clone)]
pub struct DenyProxyTargetFromInputLayer;

#[derive(Debug, Clone)]
pub struct DenyProxyTargetFromInput<S>(S);

#[inline(always)]
pub fn new_proxy_target_from_input_layer() -> DenyProxyTargetFromInputLayer {
    DenyProxyTargetFromInputLayer
}

impl<S> Layer<S> for DenyProxyTargetFromInputLayer {
    type Service = DenyProxyTargetFromInput<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DenyProxyTargetFromInput(inner)
    }
}

impl<S, Input> Service<Input> for DenyProxyTargetFromInput<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: Io + ExtensionsMut,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, _: Input) -> Result<Self::Output, Self::Error> {
        Err(BoxError::from(
            "Platform does not support L4 TProxy via this binary (Linux/Windows only)",
        ))
    }
}
