use std::{
    io::ErrorKind,
    path::PathBuf,
    sync::{Arc, LazyLock, OnceLock},
    time::Duration,
};

use clap::Parser;
use rama::{
    Layer as _, Service,
    error::OpaqueError,
    http::{
        Body, BodyExtractExt as _, Request, Response,
        client::EasyHttpWebClient,
        layer::{
            map_request_body::MapRequestBodyLayer,
            retry::{ManagedPolicy, RetryLayer},
        },
        service::client::HttpClientExt as _,
    },
    layer::{AddInputExtensionLayer, MapErrLayer, TimeoutLayer},
    net::{
        Protocol,
        address::{DomainAddress, ProxyAddress, SocketAddress},
        user::{Basic, ProxyCredential},
    },
    tls::boring::{
        client::TlsConnectorDataBuilder,
        core::x509::{X509, store::X509StoreBuilder},
    },
    utils::{backoff::ExponentialBackoff, rng::HasherRng, str::NonEmptyStr},
};

use crate::Args;

#[derive(Clone)]
pub(super) struct Runtime {
    _app: App,

    meta_addr: SocketAddress,
    proxy_addr: SocketAddress,
}

impl Runtime {
    #[inline(always)]
    pub fn meta_socket_addr(&self) -> SocketAddress {
        self.meta_addr
    }

    #[inline(always)]
    pub fn meta_domain_addr(&self) -> DomainAddress {
        DomainAddress::localhost_with_port(self.meta_addr.port)
    }

    #[inline(always)]
    pub fn proxy_socket_addr(&self) -> SocketAddress {
        self.proxy_addr
    }

    #[inline(always)]
    pub fn http_proxy_addr(&self) -> ProxyAddress {
        ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: self.proxy_socket_addr().into(),
            credential: None,
        }
    }

    #[inline(always)]
    pub fn client(&self) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        create_client_inner(None)
    }

    pub async fn client_with_ca_trust(
        &self,
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        let default_client = self.client();

        let resp = default_client
            .get(format!("http://{}/ca", self.meta_socket_addr()))
            .send()
            .await
            .unwrap();
        let payload = resp.try_into_string().await.unwrap();

        let mut store_builder = X509StoreBuilder::new().unwrap();
        store_builder
            .add_cert(X509::from_pem(payload.as_bytes()).unwrap())
            .unwrap();
        let store = Arc::new(store_builder.build());

        let tls_config =
            Arc::new(TlsConnectorDataBuilder::new_http_auto().with_server_verify_cert_store(store));

        create_client_inner(Some(tls_config))
    }

    #[inline(always)]
    pub async fn client_with_http_proxy(
        &self,
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        let web_client = self.client_with_ca_trust().await;
        AddInputExtensionLayer::new(self.http_proxy_addr()).into_layer(web_client)
    }

    #[inline(always)]
    pub async fn client_with_http_proxy_and_username(
        &self,
        username: &str,
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        let web_client = self.client_with_ca_trust().await;
        AddInputExtensionLayer::new(self.http_proxy_addr_with_username(username))
            .into_layer(web_client)
    }

    #[inline(always)]
    pub fn http_proxy_addr_with_username(&self, username: &str) -> ProxyAddress {
        ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: self.proxy_socket_addr().into(),
            credential: Some(ProxyCredential::Basic(Basic::new_insecure(
                NonEmptyStr::try_from(username).unwrap(),
            ))),
        }
    }

    #[inline(always)]
    pub async fn client_with_socks5_proxy(
        &self,
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        let web_client = self.client_with_ca_trust().await;
        AddInputExtensionLayer::new(self.socks5_proxy_addr()).into_layer(web_client)
    }

    #[inline(always)]
    pub fn socks5_proxy_addr(&self) -> ProxyAddress {
        ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: self.proxy_socket_addr().into(),
            credential: None,
        }
    }
}

fn create_client_inner(
    tls_config: Option<Arc<TlsConnectorDataBuilder>>,
) -> impl Service<Request, Output = Response, Error = OpaqueError> {
    let inner_https_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector()
        .try_with_default_connection_pool()
        .expect("create connection pool for proxy web client")
        .build_client();

    (
        MapErrLayer::new(OpaqueError::from_boxed),
        TimeoutLayer::new(Duration::from_secs(30)),
        MapErrLayer::new(Into::into),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                    0.01,
                    HasherRng::default,
                )
                .expect("create exponential backoff impl"),
            ),
        ),
        MapRequestBodyLayer::new(Body::new),
    )
        .into_layer(inner_https_client)
}

#[derive(Clone)]
struct App {
    data_dir: PathBuf,
}

pub(super) async fn get() -> Runtime {
    static APP: LazyLock<App> = LazyLock::new(App::new);

    let app = APP.clone();

    let (meta_addr, proxy_addr) = tokio::try_join!(
        tokio::time::timeout(
            Duration::from_secs(30),
            read_file_or_wait(app.data_dir.join("meta.addr.txt"))
        ),
        tokio::time::timeout(
            Duration::from_secs(30),
            read_file_or_wait(app.data_dir.join("proxy.addr.txt"))
        ),
    )
    .unwrap();

    let runtime = Runtime {
        _app: app,
        meta_addr,
        proxy_addr,
    };

    assert!(runtime.meta_socket_addr().ip_addr.is_loopback());
    assert!(runtime.proxy_socket_addr().ip_addr.is_loopback());
    assert_ne!(runtime.meta_socket_addr(), runtime.proxy_socket_addr());

    runtime
}

async fn read_file_or_wait(path: PathBuf) -> SocketAddress {
    loop {
        match tokio::fs::read_to_string(&path).await {
            Ok(s) => return s.parse().unwrap(),
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                } else {
                    panic!("unexpected error: {err}");
                }
            }
        }
    }
}

impl App {
    fn new() -> Self {
        let data_dir = spawn_safechain_proxy_app();
        Self { data_dir }
    }
}

fn spawn_safechain_proxy_app() -> PathBuf {
    let data_dir = crate::test::tmp_dir::try_new("safechain_proxy_app_e2e").unwrap();
    eprintln!("safechain_proxy_app_e2e all data stored under: {data_dir:?}");

    let data_dir_str = data_dir.display().to_string().leak();

    let args = Args::try_parse_from([
        crate::utils::env::project_name(),
        "--bind",
        "127.0.0.1:0",
        "--meta",
        "127.0.0.1:0",
        "--secrets",
        data_dir_str,
        "--data",
        data_dir_str,
        "--graceful",
        "0.42",
        "--all",
    ])
    .unwrap();

    let wait_server_ready = Arc::new(OnceLock::new());
    let notify_server_ready = wait_server_ready.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let server_future = crate::run_with_args(std::future::pending::<()>(), args);

        notify_server_ready.set(()).expect("waiter to be nofified");

        rt.block_on(server_future).expect("serve without errors");
    });

    wait_server_ready.wait();

    data_dir
}
