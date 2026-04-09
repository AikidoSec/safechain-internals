use rama::{
    error::{BoxError, ErrorContext as _},
    net::{
        proxy::ProxyTarget,
        socket::windows::{
            ProxyTargetFromWfpContext, ProxyTargetFromWfpContextLayer, WfpContextDecoder,
        },
    },
};

pub use safechain_proxy_lib_nostd::windows::redirect_ctx::ProxyRedirectContext as L4ProxyRedirectContext;

pub type ProxyTargetFromInput<S> = ProxyTargetFromWfpContext<S, L4ProxyRedirectContextDecoder>;
pub type ProxyTargetFromInputLayer = ProxyTargetFromWfpContextLayer<L4ProxyRedirectContextDecoder>;

#[inline(always)]
pub fn new_proxy_target_from_input_layer() -> ProxyTargetFromInputLayer {
    ProxyTargetFromInputLayer::new(L4ProxyRedirectContextDecoder)
}

#[derive(Debug, Clone)]
pub struct L4ProxyRedirectContextDecoder;

impl WfpContextDecoder for L4ProxyRedirectContextDecoder {
    type Context = L4ProxyRedirectContext;
    type Error = BoxError;

    fn decode(&self, bytes: &[u8]) -> Result<(Self::Context, ProxyTarget), Self::Error> {
        let ctx: L4ProxyRedirectContext = postcard::from_bytes(bytes)
            .context("decode WFP context into L4 Safechain redirect proxy context")?;
        let proxy_target = ProxyTarget(ctx.destination().into());
        Ok((ctx, proxy_target))
    }
}
