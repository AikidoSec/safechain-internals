use std::time::Duration;

use rama::{
    Layer as _, Service,
    error::OpaqueError,
    http::{
        Body, Request, Response,
        layer::{
            decompression::DecompressionLayer, map_request_body::MapRequestBodyLayer,
            map_response_body::MapResponseBodyLayer,
        },
    },
    layer::AddInputExtensionLayer,
    net::{
        Protocol,
        address::{ProxyAddress, SocketAddress},
        client::pool::http::HttpPooledConnectorConfig,
    },
    rt::Executor,
    service::BoxService,
};

use safechain_proxy_lib::client::{
    WebClientConfig, new_web_client, transport::try_set_egress_address_overwrite,
};

pub fn http_cient(
    exec: Executor,
    target: SocketAddress,
    concurrency: usize,
    proxy: bool,
) -> Result<BoxService<Request, Response, OpaqueError>, OpaqueError> {
    try_set_egress_address_overwrite(target)?;

    let pool_cfg = HttpPooledConnectorConfig {
        max_total: concurrency * 3,
        max_active: concurrency * 2,
        wait_for_pool_timeout: Some(Duration::from_secs(5)),
        idle_timeout: Some(Duration::from_secs(3)),
    };

    if proxy {
        http_client_with_shared_layers(
            AddInputExtensionLayer::new(ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: target.into(),
                credential: None,
            })
            .into_layer(new_web_client(
                exec,
                WebClientConfig::without_overwrites().with_pool_cfg(pool_cfg),
            )?),
        )
    } else {
        http_client_with_shared_layers(new_web_client(
            exec,
            WebClientConfig::default().with_pool_cfg(pool_cfg),
        )?)
    }
}

fn http_client_with_shared_layers<S>(
    inner_svc: S,
) -> Result<BoxService<Request, Response, OpaqueError>, OpaqueError>
where
    S: Service<Request, Output = Response, Error = OpaqueError>,
{
    Ok((
        MapResponseBodyLayer::new(Body::new),
        DecompressionLayer::new(),
        MapRequestBodyLayer::new(Body::new),
    )
        .into_layer(inner_svc)
        .boxed())
}
