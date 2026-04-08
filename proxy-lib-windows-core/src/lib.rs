//! Common library used by both the Windows Driver
//! (in function of Windows L4 Proxy), as well as the
//! L4 proxy when ran on Windows platforms.

#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]
#![no_std]

extern crate alloc;

pub mod driver_protocol;
pub mod redirect_ctx;
