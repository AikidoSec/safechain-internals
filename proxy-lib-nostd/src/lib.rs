//! Common library used for nostd environments,
//! such as the Windows Driver, but also used
//! for utilities common to all proxy use cases of safechain.

#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]
#![no_std]

extern crate alloc;

#[cfg(target_os = "windows")]
pub mod windows;

pub mod net;
