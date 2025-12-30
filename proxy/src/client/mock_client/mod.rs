use std::sync::Arc;

use rama::{
    Layer as _, Service,
    cli::service::echo::EchoServiceBuilder,
    error::OpaqueError,
    http::{
        Request, Response,
        matcher::HttpMatcher,
        service::web::{WebService, response::IntoResponse},
    },
    layer::MapErrLayer,
    net::address::Domain,
    service::service_fn,
    telemetry::tracing,
};

mod malware_list;
mod vscode_marketplace;

pub fn new_mock_client()
-> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, OpaqueError> {
    let echo_svc_builder = EchoServiceBuilder::default();
    let echo_svc = Arc::new(echo_svc_builder.build_http());
    let not_found_svc = service_fn(move |req| {
        let echo_svc = echo_svc.clone();
        async move { echo_svc.serve(req).await.map(IntoResponse::into_response) }
    });

    let mock_server = WebService::new()
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("malware-list.aikido.dev")),
            self::malware_list::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("marketplace.visualstudio.com")),
            self::vscode_marketplace::web_svc(),
        )
        // echo all non-blocked requests back
        .with_not_found(not_found_svc);

    tracing::warn!(
        "Mock (web) client created: do not use in production, only meant for automated testing!"
    );
    Ok(Arc::new(
        MapErrLayer::new(OpaqueError::from_std).into_layer(mock_server),
    ))
}
