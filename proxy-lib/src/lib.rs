#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

pub mod diagnostics;
pub mod endpoint_protection;
pub mod http;
pub mod package;
pub mod storage;
pub mod tcp;
pub mod tls;
pub mod utils;

pub use ::safechain_proxy_lib_nostd as nostd;
