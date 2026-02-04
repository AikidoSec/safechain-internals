//! Library for safechain proxy containing most of its core code.
//!
//! This allows the code to also be shared where desired
//! with developer tooling such as netbench.

#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

pub mod cli;
pub mod client;
pub mod diagnostics;
pub mod firewall;
pub mod http;
pub mod server;
pub mod storage;
pub mod tls;
pub mod utils;

#[cfg(test)]
pub mod test;
