use rama::{
    Layer, Service,
    error::{BoxError, extra::OpaqueError},
    extensions::ExtensionsRef,
    io::Io,
};

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
    Input: Io + ExtensionsRef,
{
    type Output = S::Output;
    type Error = OpaqueError;

    async fn serve(&self, _: Input) -> Result<Self::Output, Self::Error> {
        Err(OpaqueError::from_static_str(
            "Platform does not support L4 TProxy via this binary (Linux/Windows only)",
        ))
    }
}
