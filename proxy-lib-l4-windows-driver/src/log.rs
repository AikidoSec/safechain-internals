macro_rules! driver_log_info {
    ($($arg:tt)*) => {
        wdk::println!("[safechain-l4-windows-driver][INFO] {}", core::format_args!($($arg)*))
    };
}

macro_rules! driver_log_warn {
    ($($arg:tt)*) => {
        wdk::println!("[safechain-l4-windows-driver][WARN] {}", core::format_args!($($arg)*))
    };
}

macro_rules! driver_log_error {
    ($($arg:tt)*) => {
        wdk::println!("[safechain-l4-windows-driver][ERROR] {}", core::format_args!($($arg)*))
    };
}

pub(crate) use driver_log_error;
pub(crate) use driver_log_info;
pub(crate) use driver_log_warn;
