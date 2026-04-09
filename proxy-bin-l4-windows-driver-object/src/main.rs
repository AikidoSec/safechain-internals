#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[cfg(target_os = "windows")]
include!("main_windows.rs");

#[cfg(not(target_os = "windows"))]
include!("main_other.rs");
