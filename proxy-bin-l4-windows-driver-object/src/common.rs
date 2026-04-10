use std::{
    ffi::OsStr,
    net::{SocketAddrV4, SocketAddrV6},
    os::windows::ffi::OsStrExt,
    process::Command,
    ptr,
};

use rama_core::telemetry::tracing::{debug, info};
use safechain_proxy_lib_nostd::windows::driver_protocol::STARTUP_VALUE_NAME;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_NOT_ACTIVE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
    System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOP_PENDING,
        SERVICE_STOPPED, StartServiceW,
    },
};

pub use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY,
    IOCTL_SET_IPV6_PROXY, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload, StartupConfig,
};

pub fn start_service(service_name: &str) -> Result<(), String> {
    debug!(service_name, "starting service via SCM");
    let manager = ServiceControlManager::connect()?;
    let service = manager.open_service(service_name, SERVICE_START | SERVICE_QUERY_STATUS)?;

    let mut status = SERVICE_STATUS::default();
    if unsafe { QueryServiceStatus(service.0, &mut status) } != 0
        && (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING)
    {
        info!(service_name, state = status.dwCurrentState, "service already running");
        return Ok(());
    }

    let ok = unsafe {
        // SAFETY: service handle is valid and no argument vectors are passed.
        StartServiceW(service.0, 0, ptr::null())
    };
    if ok != 0 {
        info!(service_name, "service started successfully");
        return Ok(());
    }

    let code = unsafe { GetLastError() };
    if code == ERROR_SERVICE_ALREADY_RUNNING {
        info!(service_name, code, "service already running");
        Ok(())
    } else {
        Err(format!("failed to start service {service_name}: win32={code}"))
    }
}

pub fn stop_service(service_name: &str) -> Result<(), String> {
    debug!(service_name, "stopping service via SCM");
    let manager = ServiceControlManager::connect()?;
    let service = manager.open_service(service_name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;

    let mut status = SERVICE_STATUS::default();
    if unsafe { QueryServiceStatus(service.0, &mut status) } != 0
        && (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_STOP_PENDING)
    {
        info!(service_name, state = status.dwCurrentState, "service already stopped");
        return Ok(());
    }

    let ok = unsafe {
        // SAFETY: service handle is valid and `status` points to writable memory.
        ControlService(service.0, SERVICE_CONTROL_STOP, &mut status)
    };
    if ok != 0 {
        info!(service_name, "service stop requested successfully");
        return Ok(());
    }

    let code = unsafe { GetLastError() };
    if code == ERROR_SERVICE_NOT_ACTIVE {
        info!(service_name, code, "service already inactive");
        Ok(())
    } else {
        Err(format!("failed to stop service {service_name}: win32={code}"))
    }
}

struct ServiceControlManager(SC_HANDLE);

impl ServiceControlManager {
    fn connect() -> Result<Self, String> {
        let handle = unsafe {
            // SAFETY: null pointers select the local machine and active database.
            OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT)
        };
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            return Err(format!("failed to connect to SCM: win32={code}"));
        }
        Ok(Self(handle))
    }

    fn open_service(&self, service_name: &str, desired_access: u32) -> Result<ServiceHandle, String> {
        let wide_name = to_wide(service_name);
        let handle = unsafe {
            // SAFETY: the service name buffer is null-terminated and valid for the duration of the call.
            OpenServiceW(self.0, wide_name.as_ptr(), desired_access)
        };
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            if code == ERROR_SERVICE_DOES_NOT_EXIST {
                return Err(format!("service {service_name} does not exist: win32={code}"));
            }
            return Err(format!("failed to open service {service_name}: win32={code}"));
        }
        Ok(ServiceHandle(handle))
    }
}

impl Drop for ServiceControlManager {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: handle belongs to this wrapper and is closed once here.
                CloseServiceHandle(self.0);
            }
        }
    }
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: handle belongs to this wrapper and is closed once here.
                CloseServiceHandle(self.0);
            }
        }
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
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
