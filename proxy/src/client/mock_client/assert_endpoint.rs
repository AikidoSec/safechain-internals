use std::convert::Infallible;

use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{
        Request, Response,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
    net::user::UserId,
    telemetry::tracing,
};

use crate::server::proxy::FirewallUserConfig;

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new().with_get("/firewall-user-config/echo", safechain_config_echo)
}

async fn safechain_config_echo(req: Request) -> impl IntoResponse {
    Json(
        match req.extensions().get::<FirewallUserConfig>().cloned() {
            Some(cfg) => {
                tracing::info!(
                    "cfg found for user {:?}: {cfg:?}",
                    req.extensions().get::<UserId>()
                );
                cfg
            }
            None => {
                tracing::info!(
                    "cfg NOT found for user {:?}; return default",
                    req.extensions().get::<UserId>()
                );
                Default::default()
            }
        },
    )
}
