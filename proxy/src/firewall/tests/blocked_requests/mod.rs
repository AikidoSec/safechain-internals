use rama::{
    graceful::Shutdown,
    http::{client::EasyHttpWebClient, layer::har},
    rt::Executor,
    telemetry::tracing,
    utils::include_dir,
};

use crate::{
    firewall::{Firewall, rule::RequestAction},
    storage::SyncCompactDataStorage,
};

#[tokio::test]
#[tracing_test::traced_test]
#[ignore]
async fn test_firewall_blocked_request() {
    let data_dir = crate::test::tmp_dir::try_new("test_firewall_blocked_request").unwrap();
    tracing::info!("test_firewall_blocked_request all data stored under: {data_dir:?}");

    let shutdown = Shutdown::new(std::future::pending::<()>());
    let data_storage = SyncCompactDataStorage::try_new(data_dir).unwrap();

    let firewall = Firewall::try_new_with_event_notifier_and_web_client(
        shutdown.guard(),
        data_storage,
        None,
        EasyHttpWebClient::default_with_executor(Executor::graceful(shutdown.guard())),
    )
    .await
    .unwrap();

    static HAR_FILES: include_dir::Dir = include_dir::include_dir!(
        "$CARGO_MANIFEST_DIR/src/firewall/tests/blocked_requests/har_files"
    );

    for har_file in HAR_FILES
        .entries()
        .iter()
        .filter_map(|entry| entry.as_file())
    {
        tracing::info!(
            "check if test file {} will be correctly blocked",
            har_file.path().display(),
        );
        test_firewall_blocked_request_inner(&firewall, har_file).await;
    }
}

async fn test_firewall_blocked_request_inner(firewall: &Firewall, file: &include_dir::File<'_>) {
    let har_req: har::spec::Request = serde_json::from_slice(file.contents()).unwrap();
    let http_req = har_req.try_into().unwrap();
    let action = firewall.evaluate_request(http_req).await.unwrap();
    assert!(
        matches!(action, RequestAction::Block(_)),
        "check if test file {} will be correctly blocked",
        file.path().display()
    );
}
