use std::time::Duration;

use rama::{
    http::{BodyExtractExt as _, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{server::proxy::FirewallUserConfig, test::e2e};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_firewall_user_config_http_proxy_none() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    for uri in [
        "http://assert-test.internal/firewall-user-config/echo",
        "https://assert-test.internal/firewall-user-config/echo",
    ] {
        let resp: FirewallUserConfig = client
            .get(uri)
            .send()
            .await
            .unwrap()
            .try_into_json()
            .await
            .unwrap();
        assert_eq!(FirewallUserConfig::default(), resp, "uri = {uri}");
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_firewall_user_config_http_proxy_none_error() {
    let runtime = e2e::runtime::get().await;

    for username in ["test-min_pkg_age-foo", "test-min_pkg_age"] {
        let client = runtime.client_with_http_proxy_and_username(username).await;

        for uri in [
            "http://assert-test.internal/firewall-user-config/echo",
            "https://assert-test.internal/firewall-user-config/echo",
        ] {
            let resp: FirewallUserConfig = client
                .get(uri)
                .send()
                .await
                .unwrap()
                .try_into_json()
                .await
                .unwrap();
            assert_eq!(
                FirewallUserConfig::default(),
                resp,
                "username = {username} ; uri = {uri}",
            );
        }
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_firewall_user_config_http_proxy_fully_qualified_config() {
    let runtime = e2e::runtime::get().await;

    for username in [
        "test1-min_pkg_age-42h",
        "test2-min_pkg_age-42h-foo",
        "test3-foo-min_pkg_age-42h",
        "test4-foo-min_pkg_age-42h-foo",
        "test4-foo-min_pkg_age-41h_60m-foo",
    ] {
        let client = runtime.client_with_http_proxy_and_username(username).await;

        for uri in [
            "http://assert-test.internal/firewall-user-config/echo",
            "https://assert-test.internal/firewall-user-config/echo",
        ] {
            let resp: FirewallUserConfig = client
                .get(uri)
                .send()
                .await
                .unwrap()
                .try_into_json()
                .await
                .unwrap();
            assert_eq!(
                FirewallUserConfig {
                    min_package_age: Some(Duration::from_hours(42)),
                },
                resp,
                "username = {username} ; uri = {uri}",
            );
        }
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_firewall_user_config_http_proxy_config_header() {
    let runtime = e2e::runtime::get().await;

    let expected_cfg = FirewallUserConfig {
        min_package_age: Some(Duration::from_hours(42)),
    };

    let client = runtime
        .client_with_http_proxy_and_user_config_header(expected_cfg.clone())
        .await;

    let resp: FirewallUserConfig = client
        .get("http://assert-test.internal/firewall-user-config/echo")
        .send()
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(
        FirewallUserConfig::default(),
        resp,
        "no CONNECT request happened, so no proxy header should have been seen"
    );

    let resp: FirewallUserConfig = client
        .get("https://assert-test.internal/firewall-user-config/echo")
        .send()
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(expected_cfg, resp);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_firewall_user_config_socks5_proxy_none() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    for uri in [
        "http://assert-test.internal/firewall-user-config/echo",
        "https://assert-test.internal/firewall-user-config/echo",
    ] {
        let resp: FirewallUserConfig = client
            .get(uri)
            .send()
            .await
            .unwrap()
            .try_into_json()
            .await
            .unwrap();
        assert_eq!(FirewallUserConfig::default(), resp, "uri = {uri}");
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_firewall_user_config_socks5_proxy_fully_qualified_config() {
    let runtime = e2e::runtime::get().await;

    for username in [
        "test1-min_pkg_age-42h",
        "test2-min_pkg_age-42h-foo",
        "test3-foo-min_pkg_age-42h",
        "test4-foo-min_pkg_age-42h-foo",
        "test4-foo-min_pkg_age-41h_60m-foo",
    ] {
        let client = runtime
            .client_with_socks5_proxy_and_username(username)
            .await;

        for uri in [
            "http://assert-test.internal/firewall-user-config/echo",
            "https://assert-test.internal/firewall-user-config/echo",
        ] {
            let resp: FirewallUserConfig = client
                .get(uri)
                .send()
                .await
                .unwrap()
                .try_into_json()
                .await
                .unwrap();
            assert_eq!(
                FirewallUserConfig {
                    min_package_age: Some(Duration::from_hours(42)),
                },
                resp,
                "username = {username} ; uri = {uri}",
            );
        }
    }
}
