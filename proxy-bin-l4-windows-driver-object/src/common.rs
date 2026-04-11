use std::{
    ffi::OsStr,
    net::{SocketAddrV4, SocketAddrV6},
    os::windows::ffi::OsStrExt,
    process::Command,
    ptr::{self, null_mut},
};

use rama_core::{error::{BoxError, ErrorContext as _, ErrorExt as _}, telemetry::tracing::{debug, info}};
use safechain_proxy_lib_nostd::windows::driver_protocol::STARTUP_VALUE_NAME;
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::{
        CM_DISABLE_PERSIST, CM_Disable_DevNode, CM_Enable_DevNode, CR_SUCCESS,
        DIGCF_ALLCLASSES, HDEVINFO, SetupDiDestroyDeviceInfoList,
        SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
        SetupDiGetDeviceRegistryPropertyW, SP_DEVINFO_DATA, SPDRP_SERVICE,
    },
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA,
        ERROR_NO_MORE_ITEMS, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};

pub use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY,
    IOCTL_SET_IPV6_PROXY, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload, StartupConfig,
};

pub fn enable_device(service_name: &str) -> Result<(), BoxError> {
    debug!(service_name, "enabling device via PnP");
    let devices = find_devices_for_service(service_name)?;

    for device in &devices {
        let cr = unsafe {
            // SAFETY: `devinst` came from SetupAPI enumeration for this device info set.
            CM_Enable_DevNode(device.devinst, 0)
        };
        if cr != CR_SUCCESS {
            return Err(
                BoxError::from("failed to enable device")
                    .context_str_field("name", service_name)
                    .context_str_field("instance_id", &device.instance_id)
                    .context_field("cfgmgr32", cr),
            );
        }

        info!(service_name, instance_id = %device.instance_id, "device enabled successfully");
    }

    Ok(())
}

pub fn disable_device(service_name: &str) -> Result<(), BoxError> {
    debug!(service_name, "disabling device via PnP");
    let devices = find_devices_for_service(service_name)?;

    for device in &devices {
        let cr = unsafe {
            // SAFETY: `devinst` came from SetupAPI enumeration for this device info set.
            CM_Disable_DevNode(device.devinst, CM_DISABLE_PERSIST)
        };
        if cr != CR_SUCCESS {
            return Err(
                BoxError::from("failed to disable device")
                    .context_str_field("name", service_name)
                    .context_str_field("instance_id", &device.instance_id)
                    .context_field("cfgmgr32", cr),
            );
        }

        info!(service_name, instance_id = %device.instance_id, "device disabled successfully");
    }

    Ok(())
}

struct DeviceInfoSet(HDEVINFO);

impl DeviceInfoSet {
    fn all_classes() -> Result<Self, BoxError> {
        let handle = unsafe {
            // SAFETY: null pointers enumerate all local device classes.
            SetupDiGetClassDevsW(ptr::null(), ptr::null(), std::ptr::null_mut(), DIGCF_ALLCLASSES)
        };
        if handle == INVALID_HANDLE_VALUE as isize {
            return Err(
                BoxError::from("failed to enumerate device info set")
                    .context_field("win32", unsafe { GetLastError() }),
            );
        }
        Ok(Self(handle))
    }
}

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE as isize {
            unsafe {
                // SAFETY: handle belongs to this wrapper and is closed once here.
                SetupDiDestroyDeviceInfoList(self.0);
            }
        }
    }
}

struct MatchedDevice {
    devinst: u32,
    instance_id: String,
}

fn find_devices_for_service(service_name: &str) -> Result<Vec<MatchedDevice>, BoxError> {
    let device_info_set = DeviceInfoSet::all_classes()?;
    let mut index = 0;
    let mut devices = Vec::new();

    loop {
        let mut device_info = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..unsafe { std::mem::zeroed() }
        };

        let ok = unsafe {
            // SAFETY: `device_info` points to valid writable memory for the duration of the call.
            SetupDiEnumDeviceInfo(device_info_set.0, index, &mut device_info)
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }

            return Err(
                BoxError::from("failed to enumerate devices")
                    .context_str_field("name", service_name)
                    .context_field("win32", code),
            );
        }

        let Some(device_service_name) = query_device_service_name(device_info_set.0, &device_info)? else {
            index += 1;
            continue;
        };

        if !device_service_name.eq_ignore_ascii_case(service_name) {
            index += 1;
            continue;
        }

        let instance_id = query_device_instance_id(device_info_set.0, &device_info)?;
        devices.push(MatchedDevice {
            devinst: device_info.DevInst,
            instance_id,
        });
        index += 1;
    }

    if devices.is_empty() {
        return Err(
            BoxError::from("no PnP device found for service")
                .context_str_field("name", service_name),
        );
    }

    Ok(devices)
}

fn query_device_service_name(
    device_info_set: HDEVINFO,
    device_info: &SP_DEVINFO_DATA,
) -> Result<Option<String>, BoxError> {
    query_device_registry_string_property(device_info_set, device_info, SPDRP_SERVICE)
}

fn query_device_registry_string_property(
    device_info_set: HDEVINFO,
    device_info: &SP_DEVINFO_DATA,
    property: u32,
) -> Result<Option<String>, BoxError> {
    let mut property_type = 0;
    let mut required_size = 0;
    let ok = unsafe {
        // SAFETY: probing for the required size with a null buffer is supported by SetupAPI.
        SetupDiGetDeviceRegistryPropertyW(
            device_info_set,
            device_info,
            property,
            &mut property_type,
            null_mut(),
            0,
            &mut required_size,
        )
    };
    if ok != 0 {
        return Ok(Some(String::new()));
    }

    let code = unsafe { GetLastError() };
    if code == ERROR_INVALID_DATA {
        return Ok(None);
    }
    if code != ERROR_INSUFFICIENT_BUFFER || required_size == 0 {
        return Err(
            BoxError::from("failed to query device registry property")
                .context_field("property", property)
                .context_field("win32", code),
        );
    }

    let mut buffer = vec![0_u16; (required_size as usize).div_ceil(2)];
    let ok = unsafe {
        // SAFETY: `buffer` is writable and sized from the required byte count reported by SetupAPI.
        SetupDiGetDeviceRegistryPropertyW(
            device_info_set,
            device_info,
            property,
            &mut property_type,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * std::mem::size_of::<u16>()) as u32,
            &mut required_size,
        )
    };
    if ok == 0 {
        return Err(
            BoxError::from("failed to read device registry property")
                .context_field("property", property)
                .context_field("win32", unsafe { GetLastError() }),
        );
    }

    Ok(Some(from_wide_with_nul(&buffer)))
}

fn query_device_instance_id(
    device_info_set: HDEVINFO,
    device_info: &SP_DEVINFO_DATA,
) -> Result<String, BoxError> {
    let mut required_size = 0;
    let ok = unsafe {
        // SAFETY: probing for the required size with a null buffer is supported by SetupAPI.
        SetupDiGetDeviceInstanceIdW(device_info_set, device_info, null_mut(), 0, &mut required_size)
    };
    if ok != 0 {
        return Ok(String::new());
    }

    let code = unsafe { GetLastError() };
    if code != ERROR_INSUFFICIENT_BUFFER || required_size == 0 {
        return Err(
            BoxError::from("failed to query device instance id size")
                .context_field("win32", code),
        );
    }

    let mut buffer = vec![0_u16; required_size as usize];
    let ok = unsafe {
        // SAFETY: `buffer` is writable and sized from the required character count reported by SetupAPI.
        SetupDiGetDeviceInstanceIdW(
            device_info_set,
            device_info,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut required_size,
        )
    };
    if ok == 0 {
        return Err(
            BoxError::from("failed to read device instance id")
                .context_field("win32", unsafe { GetLastError() }),
        );
    }

    Ok(from_wide_with_nul(&buffer))
}

fn from_wide_with_nul(value: &[u16]) -> String {
    let end = value.iter().position(|&ch| ch == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

pub fn write_startup_blob(service_name: &str, blob: &StartupConfig) -> Result<(), BoxError> {
    let key_path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}\Parameters");
    let encoded = blob
        .to_bytes()
        .context("failed to encode startup config")?;

    let hex_blob = hex::encode_upper(&encoded);
    debug!(
        service_name,
        bytes = encoded.len(),
        "writing startup blob to registry"
    );

    let create_key = Command::new("reg.exe")
        .args(["add", &key_path, "/f"])
        .output()
        .context("failed to create/open registry key")
        .with_context_field("key_path", || key_path.clone())?;

    if !create_key.status.success() {
        return Err(BoxError::from(
            "reg.exe add key failed"
        ).context_str_field("stderr", String::from_utf8_lossy(&create_key.stderr).trim()));
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
        return Err(BoxError::from(
            "reg.exe add value failed"
        ).context_str_field("stderr", String::from_utf8_lossy(&write_value.stderr).trim()));
    }

    info!(service_name, "startup blob written to registry");
    Ok(())
}

pub fn read_startup_blob(service_name: &str) -> Result<Option<StartupConfig>, BoxError> {
    let key_path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}\Parameters");
    debug!(service_name, "reading startup blob from registry");
    let output = Command::new("reg.exe")
        .args(["query", &key_path, "/v", STARTUP_VALUE_NAME])
        .output()
        .context("failed to query startup blob")?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // TODO: find a non-locale aware way to do this
        // if stdout.contains("unable to find") || stderr.contains("unable to find") {
        //     debug!(service_name, "startup blob is not present in registry");
        //     return Ok(None);
        // }

        

        return Err(BoxError::from("reg.exe query value failed")
            .context_str_field("stdout", stdout.trim())
            .context_str_field("stderr", stderr.trim()));
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
) -> Result<(), BoxError> {
    let current = read_startup_blob(service_name)?;

    let next_ipv4 = match (ipv4_proxy, current.as_ref().map(StartupConfig::proxy_ipv4)) {
        (Some(ipv4), _) => ipv4,
        (None, Some(ipv4)) => ipv4,
        (None, None) => {
            return Err(BoxError::from(
                "cannot update persisted startup config without an existing IPv4 proxy; use `enable` or pass `--ipv4-proxy`"
            ))
        }
    };

    let next_ipv6 = match ipv6_proxy {
        Some(next) => next,
        None => current.and_then(|blob| blob.proxy_ipv6()),
    };

    write_startup_blob(service_name, &StartupConfig::new(next_ipv4, next_ipv6))
}

pub fn delete_startup_blob(service_name: &str) -> Result<(), BoxError> {
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

    // TODO: need to find non-locale aware way to fix this
    // if stdout.contains("unable to find") || stderr.contains("unable to find") {
    //     debug!(service_name, "startup blob was already absent");
    //     return Ok(());
    // }

    Err(
        BoxError::from("reg.exe delete value failed")
            .context_str_field("stdout", stdout.trim())
            .context_str_field("stderr", stderr.trim())
    )
}

pub struct DeviceHandle(HANDLE);

impl DeviceHandle {
    pub fn open(device_path: &str) -> Result<Self, BoxError> {
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
            return Err(
                BoxError::from("failed to open device")
                .context_str_field("device_path", device_path)
                .context_field("win32", unsafe { GetLastError() })
            );
        }

        info!(device_path, "opened driver device handle");
        Ok(Self(handle))
    }

    pub fn send_ioctl(&self, ioctl: u32, input: &[u8]) -> Result<(), BoxError> {
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
            return Err(
                BoxError::from("DeviceIoControl failed for ioctl")
                .context_hex_field("ioctl", ioctl)
                .context_field("win32", unsafe { GetLastError() })
            );
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
