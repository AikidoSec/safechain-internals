use std::sync::Arc;

use rama::{
    Layer as _, Service,
    error::OpaqueError,
    http::{Request, Response, service::web::Router},
    layer::MapErrLayer,
    telemetry::tracing,
};

pub fn new_mock_client()
-> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, OpaqueError> {
    let mock_server = Router::new();

    tracing::warn!(
        "Mock (web) client created: do not use in production, only meant for automated testing!"
    );
    Ok(Arc::new(
        MapErrLayer::new(OpaqueError::from_std).into_layer(mock_server),
    ))
}
