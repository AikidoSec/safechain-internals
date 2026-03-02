use std::sync::{Arc, LazyLock};

use rama::{
    Layer as _, Service,
    cli::service::echo::EchoServiceBuilder,
    error::{BoxError, extra::OpaqueError},
    http::{
        Request, Response,
        matcher::HttpMatcher,
        service::web::{WebService, response::IntoResponse},
    },
    layer::MapErrLayer,
    net::address::Domain,
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};
use safechain_proxy_lib::utils::env::aikido_app_base_url;

mod assert_endpoint;
mod endpoint_protection_callbacks;
mod malware_list;
mod vscode_marketplace;

static ASSERT_ENDPOINT_STATE: LazyLock<assert_endpoint::MockState> =
    LazyLock::new(assert_endpoint::MockState::new);

pub fn new_mock_client()
-> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    let echo_svc_builder = EchoServiceBuilder::default();
    let echo_svc = Arc::new(echo_svc_builder.build_http(Executor::default()));
    let not_found_svc = service_fn(move |req| {
        let echo_svc = echo_svc.clone();
        async move { echo_svc.serve(req).await.map(IntoResponse::into_response) }
    });

    let app_domain = app_domain_from_base_url();

    let mock_server = WebService::new()
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("malware-list.aikido.dev")),
            self::malware_list::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("marketplace.visualstudio.com")),
            self::vscode_marketplace::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(app_domain),
            self::endpoint_protection_callbacks::web_svc(),
        )
        .with_matcher(
            HttpMatcher::domain(Domain::from_static("assert-test.internal")),
            self::assert_endpoint::web_svc(ASSERT_ENDPOINT_STATE.clone()),
        )
        // echo all non-blocked requests back
        .with_not_found(not_found_svc);

    tracing::warn!(
        "Mock (web) client created: do not use in production, only meant for automated testing!"
    );
    Ok(Arc::new(
        MapErrLayer::into_opaque_error().into_layer(mock_server),
    ))
}

fn app_domain_from_base_url() -> Domain {
    let host = aikido_app_base_url()
        .host()
        .expect("aikido app base URL should always have a host");
    host.parse::<Domain>()
        .expect("aikido app base URL host should be a valid domain")
}
