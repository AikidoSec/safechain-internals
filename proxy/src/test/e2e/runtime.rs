use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Duration,
};

use clap::Parser;
use rama::{
    net::{
        address::{DomainAddress, SocketAddress},
        socket::core::Socket,
    },
    telemetry::tracing,
};

use crate::Args;

#[derive(Clone)]
pub(super) struct Runtime {
    app: App,

    meta_addr: SocketAddress,
    proxy_addr: SocketAddress,
}

impl Runtime {
    #[inline(always)]
    pub fn meta_addr(&self) -> SocketAddress {
        self.meta_addr
    }

    #[inline(always)]
    pub fn meta_domain_addr(&self) -> DomainAddress {
        DomainAddress::localhost_with_port(self.meta_addr.port)
    }

    #[inline(always)]
    pub fn proxy_addr(&self) -> SocketAddress {
        self.proxy_addr
    }
}

#[derive(Clone)]
struct App {
    data_dir: PathBuf,
}

pub(super) async fn get() -> Runtime {
    static APP: LazyLock<App> = LazyLock::new(App::new);

    let app = APP.clone();

    let meta_addr = tokio::time::timeout(
        Duration::from_secs(10),
        read_file_or_wait(app.data_dir.join("meta.addr.txt")),
    )
    .await
    .unwrap();

    let proxy_addr = tokio::time::timeout(
        Duration::from_secs(10),
        read_file_or_wait(app.data_dir.join("proxy.addr.txt")),
    )
    .await
    .unwrap();

    Runtime {
        app,
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
        "--pretty",
        "--output",
        data_dir
            .join("safechain_proxy_app_e2e.log.txt")
            .display()
            .to_string()
            .leak(),
        "--data",
        data_dir_str,
        "--graceful",
        "0.42",
        "--all",
    ])
    .unwrap();

    if let Err(err) = crate::utils::telemetry::init_tracing(&args) {
        tracing::warn!(
            "failed to init tracing (already created perhaps by other test?): err = {err}"
        );
    }

    tokio::spawn(async move {
        crate::run_with_args(std::future::pending::<()>(), args)
            .await
            .unwrap();
    });

    data_dir
}
