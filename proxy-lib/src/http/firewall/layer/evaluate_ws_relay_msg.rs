use rama::{
    Service,
    error::BoxError,
    http::ws::handshake::mitm::{WebSocketRelayInput, WebSocketRelayOutput},
};

use crate::http::firewall::Firewall;

#[derive(Debug, Clone)]
pub struct EvaluateWsRelayMsgService(pub(in crate::http::firewall) Firewall);

impl Service<WebSocketRelayInput> for EvaluateWsRelayMsgService {
    type Output = WebSocketRelayOutput;
    type Error = BoxError;

    async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
        self.0.evaluate_ws_relay_msg(input).await
    }
}
