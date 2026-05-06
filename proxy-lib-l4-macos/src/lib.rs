#![cfg(target_os = "macos")]

use rama::net::apple::networkextension::{
    tproxy::TransparentProxyEngineBuilder, transparent_proxy_ffi,
};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod config;
mod handler;
mod init;
mod state;
mod tcp;
mod tls;
mod utils;
mod xpc_server;

transparent_proxy_ffi! {
    init = self::init::init,
    engine_builder = TransparentProxyEngineBuilder::new(
        self::handler::FlowHandlerFactory
    ),
}
