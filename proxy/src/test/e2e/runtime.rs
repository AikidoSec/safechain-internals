use std::{io::ErrorKind, path::PathBuf, sync::LazyLock, time::Duration};

use clap::Parser;
use rama::{
    net::{
        Protocol,
        address::{DomainAddress, ProxyAddress, SocketAddress},
        user::{Basic, ProxyCredential},
    },
    utils::str::NonEmptyStr,
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
    #[expect(unused)] // NOTE: remove the unused exception first time you need it
    pub fn http_proxy_addr_with_username(&self, username: &'static str) -> ProxyAddress {
        ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: self.proxy_socket_addr().into(),
            credential: Some(ProxyCredential::Basic(Basic::new_insecure(
                NonEmptyStr::try_from(username).unwrap(),
            ))),
        }
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

    Runtime {
        _app: app,
        meta_addr,
        proxy_addr,
    }
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

    tokio::spawn(async move {
        crate::run_with_args(std::future::pending::<()>(), args)
            .await
            .unwrap();
    });

    data_dir
}
