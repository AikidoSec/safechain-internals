use std::{sync::Arc, time::Duration};

use rama::{
    Layer as _, Service,
    error::OpaqueError,
    graceful::ShutdownGuard,
    http::{
        Request, Response, StatusCode, Uri,
        layer::traffic_writer::{
            BidirectionalWriter, RequestWriterLayer, ResponseWriterLayer, WriterMode,
        },
        service::web::{
            Router,
            extract::{Json, State},
            response::IntoResponse,
        },
    },
    layer::MapErrLayer,
    rt::Executor,
    service::BoxService,
    utils::collections::AppendOnlyVec,
};

use safechain_proxy_lib::{
    firewall::{Firewall, events::BlockedEvent, notifier::EventNotifier},
    storage::SyncCompactDataStorage,
};
use tokio::sync::Mutex;

use crate::cmd::emulate::Source;

#[derive(Debug, Clone)]
pub(super) struct Client {
    shared_data: Data,
    web_svc: BoxService<Request, Response, OpaqueError>,
}

pub(super) async fn new_client(
    guard: ShutdownGuard,
    data_storage: SyncCompactDataStorage,
    source: Source,
) -> Result<Client, OpaqueError> {
    let shared_data = Data::default();

    let exec = Executor::graceful(guard.clone());

    let traffic_writer = BidirectionalWriter::stdout_unbounded(
        &exec,
        Some(WriterMode::Headers),
        Some(WriterMode::Headers),
    );

    let notifier_web_client = Arc::new(
        MapErrLayer::new(OpaqueError::from_std).into_layer(
            Router::new_with_state(shared_data.clone())
                .with_post("/blocked-event", report_blocked_event),
        ),
    );
    let notifier = EventNotifier::try_new_with_client(
        exec,
        Uri::from_static("https://notifier.fake-aikido.internal/blocked-event"),
        notifier_web_client,
    )?;

    let firewall =
        Firewall::try_new_with_event_notifier(guard, data_storage, Some(notifier)).await?;

    let web_svc = (
        MapErrLayer::new(OpaqueError::from_boxed),
        RequestWriterLayer::new(traffic_writer.clone()),
        ResponseWriterLayer::new(traffic_writer),
        firewall.clone().into_evaluate_request_layer(),
        firewall.into_evaluate_response_layer(),
    )
        .into_layer(MockHttpClient {
            source: Arc::new(Mutex::new(source)),
        })
        .boxed();

    Ok(Client {
        shared_data,
        web_svc,
    })
}

impl Service<Request> for Client {
    type Output = Response;
    type Error = OpaqueError;

    #[inline(always)]
    fn serve(
        &self,
        req: Request,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.web_svc.serve(req)
    }
}

impl Client {
    pub(super) async fn wait_for_blocked_events(&self) -> Result<(), OpaqueError> {
        for _ in 1..10 {
            if !self.shared_data.blocked_events.is_empty() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(OpaqueError::from_display(
            "failed to wait for blocked events",
        ))
    }

    pub(super) fn blocked_events(&self) -> impl Iterator<Item = &BlockedEvent> {
        self.shared_data.blocked_events.iter()
    }
}

#[derive(Debug, Clone)]
struct MockHttpClient {
    source: Arc<Mutex<Source>>,
}

impl Service<Request> for MockHttpClient {
    type Output = Response;
    type Error = OpaqueError;

    #[inline(always)]
    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        self.source.lock().await.next_response_for(req).await
    }
}

#[derive(Debug, Clone, Default)]
struct Data {
    blocked_events: Arc<AppendOnlyVec<BlockedEvent>>,
}

async fn report_blocked_event(
    State(Data { blocked_events }): State<Data>,
    Json(event): Json<BlockedEvent>,
) -> impl IntoResponse {
    blocked_events.push(event);
    StatusCode::OK
}
