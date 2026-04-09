use std::{
    ffi::OsStr,
    net::{SocketAddrV4, SocketAddrV6},
    os::windows::ffi::OsStrExt,
    process::Command,
};

use rama::telemetry::tracing::{debug, info};
use safechain_proxy_lib_nostd::windows::driver_protocol::STARTUP_VALUE_NAME;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};

pub use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_CLEAR_PROXY_PROCESS_ID, IOCTL_SET_IPV4_PROXY,
    IOCTL_SET_IPV6_PROXY, IOCTL_SET_PROXY_PROCESS_ID, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload, ProxyProcessIdPayload, StartupConfig,
};

pub fn run_sc(args: &[&str], allowed_marker: &str) -> Result<(), String> {
    debug!(?args, allowed_marker, "running sc.exe command");
    let output = Command::new("sc.exe")
        .args(args)
        .output()
        .map_err(|err| format!("failed to run sc.exe {args:?}: {err}"))?;

    if output.status.success() {
        info!(?args, "sc.exe command completed successfully");
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.contains(allowed_marker) || stderr.contains(allowed_marker) {
        debug!(?args, allowed_marker, "sc.exe returned allowed marker");
        return Ok(());
    }

    Err(format!(
        "sc.exe {args:?} failed: {}{}",
        stdout.trim(),
        if stderr.trim().is_empty() {
            String::new()
        } else {
            format!(" {}", stderr.trim())
        }
    ))
}

pub fn write_startup_blob(service_name: &str, blob: &StartupConfig) -> Result<(), String> {
    let key_path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}\Parameters");
    let encoded = blob
        .to_bytes()
        .map_err(|err| format!("failed to encode startup config: {err}"))?;
    let hex_blob = hex::encode_upper(&encoded);
    debug!(
        service_name,
        bytes = encoded.len(),
        "writing startup blob to registry"
    );

    let create_key = Command::new("reg.exe")
        .args(["add", &key_path, "/f"])
        .output()
        .map_err(|err| format!("failed to create/open registry key {key_path}: {err}"))?;
    if !create_key.status.success() {
        return Err(format!(
            "reg.exe add key failed: {}",
            String::from_utf8_lossy(&create_key.stderr).trim()
        ));
    }

    let write_value = Command::new("reg.exe")
        .args([
            "add",
            &key_path,
            "/v",
            STARTUP_VALUE_NAME,
            "/t",
            "REG_BINARY",
            "/d",
            &hex_blob,
            "/f",
        ])
        .output()
        .map_err(|err| format!("failed to write startup blob: {err}"))?;
    if !write_value.status.success() {
        return Err(format!(
            "reg.exe add value failed: {}",
            String::from_utf8_lossy(&write_value.stderr).trim()
        ));
    }

    info!(service_name, "startup blob written to registry");
    Ok(())
}

pub fn read_startup_blob(service_name: &str) -> Result<Option<StartupConfig>, String> {
    let key_path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}\Parameters");
    debug!(service_name, "reading startup blob from registry");
    let output = Command::new("reg.exe")
        .args(["query", &key_path, "/v", STARTUP_VALUE_NAME])
        .output()
        .map_err(|err| format!("failed to query startup blob: {err}"))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stdout.contains("unable to find") || stderr.contains("unable to find") {
            debug!(service_name, "startup blob is not present in registry");
            return Ok(None);
        }
        return Err(format!(
            "reg.exe query value failed: {} {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hex_blob = stdout
        .lines()
        .find_map(|line| {
            if line.contains(STARTUP_VALUE_NAME) && line.contains("REG_BINARY") {
                line.split("REG_BINARY").nth(1).map(str::trim)
            } else {
                None
            }
        })
        .ok_or_else(|| format!("failed to parse REG_BINARY output for {STARTUP_VALUE_NAME}"))?;

    let bytes = hex::decode(hex_blob)
        .map_err(|err| format!("failed to decode registry hex payload: {err}"))?;
    let blob = StartupConfig::from_bytes(&bytes)
        .ok_or_else(|| "failed to decode startup config blob".to_string())?;
    Ok(Some(blob))
}

pub fn sync_startup_blob(
    service_name: &str,
    ipv4_proxy: Option<SocketAddrV4>,
    ipv6_proxy: Option<Option<SocketAddrV6>>,
) -> Result<(), String> {
    let current = read_startup_blob(service_name)?;

    let next_ipv4 = match (ipv4_proxy, current.as_ref().map(StartupConfig::proxy_ipv4)) {
        (Some(ipv4), _) => ipv4,
        (None, Some(ipv4)) => ipv4,
        (None, None) => {
            return Err(
                "cannot update persisted startup config without an existing IPv4 proxy; use `start` or pass `--ipv4-proxy`".to_string(),
            )
        }
    };

    let next_ipv6 = match ipv6_proxy {
        Some(next) => next,
        None => current.and_then(|blob| blob.proxy_ipv6()),
    };

    write_startup_blob(service_name, &StartupConfig::new(next_ipv4, next_ipv6))
}

pub fn delete_startup_blob(service_name: &str) -> Result<(), String> {
    let key_path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}\Parameters");
    debug!(service_name, "deleting startup blob from registry");
    let output = Command::new("reg.exe")
        .args(["delete", &key_path, "/v", STARTUP_VALUE_NAME, "/f"])
        .output()
        .map_err(|err| format!("failed to delete startup blob: {err}"))?;

    if output.status.success() {
        info!(service_name, "startup blob deleted from registry");
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.contains("unable to find") || stderr.contains("unable to find") {
        debug!(service_name, "startup blob was already absent");
        return Ok(());
    }

    Err(format!(
        "reg.exe delete value failed: {} {}",
        stdout.trim(),
        stderr.trim()
    ))
}

pub struct DeviceHandle(HANDLE);

impl DeviceHandle {
    pub fn open(device_path: &str) -> Result<Self, String> {
        debug!(device_path, "opening driver device handle");
        let mut wide_path: Vec<u16> = OsStr::new(device_path).encode_wide().collect();
        wide_path.push(0);

        let handle = unsafe {
            // SAFETY: `wide_path` is null-terminated and valid for the duration of the call.
            CreateFileW(
                wide_path.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "failed to open device {}: win32={}",
                device_path,
                unsafe { GetLastError() }
            ));
        }

        info!(device_path, "opened driver device handle");
        Ok(Self(handle))
    }

    pub fn send_ioctl(&self, ioctl: u32, input: &[u8]) -> Result<(), String> {
        debug!(
            ioctl = format_args!("{ioctl:#x}"),
            input_len = input.len(),
            "sending driver ioctl"
        );
        let mut bytes_returned = 0_u32;
        let ok = unsafe {
            // SAFETY: handle is owned by `self`; buffer pointers are valid for the stated lengths.
            DeviceIoControl(
                self.0,
                ioctl,
                if input.is_empty() {
                    std::ptr::null_mut()
                } else {
                    input.as_ptr().cast_mut().cast()
                },
                input.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "DeviceIoControl failed for ioctl {ioctl:#x}: win32={}",
                unsafe { GetLastError() }
            ));
        }

        debug!(ioctl = format_args!("{ioctl:#x}"), "driver ioctl completed");
        Ok(())
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                // SAFETY: the handle belongs to this instance and is closed exactly once here.
                CloseHandle(self.0);
            }
        }
    }
}
