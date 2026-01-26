#[cfg(target_family = "unix")]
mod unix;

#[cfg(target_family = "unix")]
pub use self::unix::raise_nofile;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use self::windows::raise_nofile;
