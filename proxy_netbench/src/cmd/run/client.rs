use rama::{
    Layer as _, Service as _,
    error::OpaqueError,
    http::{Request, Response},
    layer::AddInputExtensionLayer,
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
    },
    rt::Executor,
    service::BoxService,
};
use safechain_proxy_lib::client::{new_web_client, transport::try_set_egress_address_overwrite};

pub fn http_cient(
    exec: Executor,
    target: SocketAddress,
    proxy: bool,
) -> Result<BoxService<Request, Response, OpaqueError>, OpaqueError> {
    if proxy {
        Ok(AddInputExtensionLayer::new(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: target.into(),
            credential: None,
        })
        .into_layer(new_web_client(exec)?)
        .boxed())
    } else {
        try_set_egress_address_overwrite(target)?;
        Ok(new_web_client(exec)?.boxed())
    }
}
