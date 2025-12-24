mod no_firewall;

mod firewall_chrome;
mod firewall_npm;
mod firewall_vscode;

use rama::{Layer as _, layer::AddInputExtensionLayer};

use crate::test::e2e;

pub(super) async fn test_proxy(runtime: &e2e::runtime::Runtime) {
    let client = AddInputExtensionLayer::new(runtime.http_proxy_addr())
        .into_layer(e2e::client::new_web_client(runtime, true).await);

    tokio::join!(
        self::no_firewall::test_http_example_com_proxy_http(&client),
        self::no_firewall::test_http_example_com_proxy_socks5(runtime, &client),
        self::no_firewall::test_https_example_com_proxy_http(&client),
        self::no_firewall::test_https_example_com_proxy_socks5(runtime, &client),
    );

    self::firewall_chrome::test_google_har_replay_blocked_plugin(&client).await;

    tokio::join!(
        self::firewall_vscode::test_vscode_http_plugin_malware_blocked(&client),
        self::firewall_vscode::test_vscode_http_plugin_ok(&client),
        self::firewall_vscode::test_vscode_https_plugin_malware_blocked(&client),
        self::firewall_vscode::test_vscode_https_plugin_ok(&client),
    );

    tokio::join!(
        self::firewall_npm::test_npm_https_package_malware_blocked(&client),
        self::firewall_npm::test_npm_https_package_ok(&client),
    );
}
