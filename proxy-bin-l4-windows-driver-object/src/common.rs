use std::{
    ffi::OsStr,
    net::{SocketAddrV4, SocketAddrV6},
    os::windows::ffi::OsStrExt,
    ptr::{self, null_mut},
    thread,
    time::Duration,
};

use rama_core::{error::{BoxError, ErrorContext as _, ErrorExt as _}, telemetry::tracing::{debug, info, warn}};
use safechain_proxy_lib_nostd::windows::driver_protocol::STARTUP_VALUE_NAME;
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::{
        CM_DISABLE_ABSOLUTE, CM_DISABLE_PERSIST, CM_DISABLE_UI_NOT_OK, CM_Disable_DevNode,
        CM_Enable_DevNode, CR_ACCESS_DENIED, CR_ALREADY_SUCH_DEVINST, CR_APM_VETOED,
        CR_BUFFER_SMALL, CR_CALL_NOT_IMPLEMENTED, CR_CANT_SHARE_IRQ, CR_CREATE_BLOCKED,
        CR_DEFAULT, CR_DEVICE_INTERFACE_ACTIVE, CR_DEVICE_NOT_THERE, CR_DEVINST_HAS_REQS,
        CR_DEVLOADER_NOT_READY, CR_FAILURE, CR_FREE_RESOURCES, CR_INVALID_API,
        CR_INVALID_ARBITRATOR, CR_INVALID_CONFLICT_LIST, CR_INVALID_DATA, CR_INVALID_DEVICE_ID,
        CR_INVALID_DEVINST, CR_INVALID_FLAG, CR_INVALID_INDEX, CR_INVALID_LOAD_TYPE,
        CR_INVALID_LOG_CONF, CR_INVALID_MACHINENAME, CR_INVALID_NODELIST, CR_INVALID_POINTER,
        CR_INVALID_PRIORITY, CR_INVALID_PROPERTY, CR_INVALID_RANGE, CR_INVALID_RANGE_LIST,
        CR_INVALID_REFERENCE_STRING, CR_INVALID_RESOURCEID, CR_INVALID_RES_DES,
        CR_INVALID_STRUCTURE_SIZE, CR_MACHINE_UNAVAILABLE, CR_NEED_RESTART, CR_NOT_DISABLEABLE,
        CR_NOT_SYSTEM_VM, CR_NO_ARBITRATOR, CR_NO_CM_SERVICES, CR_NO_DEPENDENT,
        CR_NO_MORE_HW_PROFILES, CR_NO_MORE_LOG_CONF, CR_NO_MORE_RES_DES,
        CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_DEVINST, CR_NO_SUCH_LOGICAL_DEV,
        CR_NO_SUCH_REGISTRY_KEY, CR_NO_SUCH_VALUE, CR_OUT_OF_MEMORY, CR_QUERY_VETOED,
        CR_REGISTRY_ERROR, CR_REMOTE_COMM_FAILURE, CR_REMOVE_VETOED, CR_SAME_RESOURCES,
        CR_SUCCESS, CR_WRONG_TYPE, CM_Uninstall_DevNode,
        DIGCF_ALLCLASSES, HDEVINFO, SetupDiDestroyDeviceInfoList,
        SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
        SetupDiGetDeviceRegistryPropertyW, SP_DEVINFO_DATA, SPDRP_SERVICE,
    },
    Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
        ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
    System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE,
        KEY_SET_VALUE, REG_BINARY, REG_OPTION_NON_VOLATILE,
    },
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
        let restart_disable_cr = unsafe {
            // SAFETY: `devinst` came from SetupAPI enumeration for this device info set.
            CM_Disable_DevNode(device.devinst, ENABLE_RESTART_DISABLE_FLAGS)
        };
        match restart_disable_cr {
            CR_SUCCESS => {
                info!(
                    service_name,
                    instance_id = %device.instance_id,
                    "device disabled transiently to force a driver reload"
                );
                thread::sleep(Duration::from_millis(150));
            }
            CR_REMOVE_VETOED | CR_NOT_DISABLEABLE | CR_NO_SUCH_DEVINST | CR_DEVICE_NOT_THERE => {
                warn!(
                    service_name,
                    instance_id = %device.instance_id,
                    cfgmgr32 = configret_name(restart_disable_cr),
                    "could not force a transient device restart before enable; continuing with enable"
                );
            }
            _ => {
                return Err(
                    BoxError::from("failed to prepare device restart before enable")
                        .context_str_field("name", service_name)
                        .context_str_field("instance_id", &device.instance_id)
                        .context_field("cfgmgr32", restart_disable_cr)
                        .context_str_field("cfgmgr32_name", configret_name(restart_disable_cr)),
                );
            }
        }

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

pub fn disable_device(service_name: &str, force_remove_on_veto: bool) -> Result<(), BoxError> {
    debug!(service_name, "disabling device via PnP");
    let devices = find_devices_for_service(service_name)?;
    if devices.is_empty() {
        info!(service_name, "no matching PnP device found; treating disable as already complete");
        return Ok(());
    }

    for device in &devices {
        info!(
            service_name,
            instance_id = %device.instance_id,
            "attempting to disable device"
        );
        let cr = disable_devinst_with_retry(device.devinst, &device.instance_id);
        if cr == CR_REMOVE_VETOED && force_remove_on_veto {
            warn!(
                service_name,
                instance_id = %device.instance_id,
                "disable was vetoed; force-removing device instance subtree"
            );
            let remove_cr = force_remove_devinst(device.devinst, &device.instance_id);
            if remove_cr != CR_SUCCESS {
                return Err(
                    BoxError::from("failed to force-remove device after disable veto")
                        .context_str_field("name", service_name)
                        .context_str_field("instance_id", &device.instance_id)
                        .context_field("cfgmgr32", remove_cr)
                        .context_str_field("cfgmgr32_name", configret_name(remove_cr)),
                );
            }

            info!(
                service_name,
                instance_id = %device.instance_id,
                "device force-removed successfully"
            );
            continue;
        }

        if cr != CR_SUCCESS {
            return Err(
                BoxError::from("failed to disable device")
                    .context_str_field("name", service_name)
                    .context_str_field("instance_id", &device.instance_id)
                    .context_field("cfgmgr32", cr)
                    .context_str_field("cfgmgr32_name", configret_name(cr)),
            );
        }

        info!(service_name, instance_id = %device.instance_id, "device disabled successfully");
    }

    Ok(())
}

const DISABLE_FLAGS: u32 = CM_DISABLE_ABSOLUTE | CM_DISABLE_PERSIST | CM_DISABLE_UI_NOT_OK;
const ENABLE_RESTART_DISABLE_FLAGS: u32 = CM_DISABLE_UI_NOT_OK;
const DISABLE_RETRY_DELAYS_MS: &[u64] = &[150, 500, 1000];
fn disable_devinst_with_retry(devinst: u32, instance_id: &str) -> u32 {
    let mut attempt = 0usize;
    loop {
        let cr = unsafe {
            // SAFETY: `devinst` came from SetupAPI enumeration for this device info set.
            CM_Disable_DevNode(devinst, DISABLE_FLAGS)
        };
        if cr == CR_SUCCESS {
            return cr;
        }

        if cr != CR_REMOVE_VETOED || attempt >= DISABLE_RETRY_DELAYS_MS.len() {
            return cr;
        }

        let delay_ms = DISABLE_RETRY_DELAYS_MS[attempt];
        warn!(
            instance_id,
            cfgmgr32 = configret_name(cr),
            delay_ms,
            "device disable was vetoed; retrying"
        );
        thread::sleep(Duration::from_millis(delay_ms));
        attempt += 1;
    }
}

fn force_remove_devinst(devinst: u32, instance_id: &str) -> u32 {
    let cr = unsafe {
        // SAFETY: `devinst` came from SetupAPI enumeration for this device info set.
        CM_Uninstall_DevNode(devinst, 0)
    };
    if cr != CR_SUCCESS {
        warn!(
            instance_id,
            cfgmgr32 = configret_name(cr),
            "force-remove of device instance subtree failed"
        );
    }
    cr
}

fn configret_name(code: u32) -> &'static str {
    match code {
        CR_SUCCESS => "CR_SUCCESS",
        CR_DEFAULT => "CR_DEFAULT",
        CR_OUT_OF_MEMORY => "CR_OUT_OF_MEMORY",
        CR_INVALID_POINTER => "CR_INVALID_POINTER",
        CR_INVALID_FLAG => "CR_INVALID_FLAG",
        CR_INVALID_DEVINST => "CR_INVALID_DEVINST",
        CR_INVALID_RES_DES => "CR_INVALID_RES_DES",
        CR_INVALID_LOG_CONF => "CR_INVALID_LOG_CONF",
        CR_INVALID_ARBITRATOR => "CR_INVALID_ARBITRATOR",
        CR_INVALID_NODELIST => "CR_INVALID_NODELIST",
        CR_DEVINST_HAS_REQS => "CR_DEVINST_HAS_REQS",
        CR_INVALID_RESOURCEID => "CR_INVALID_RESOURCEID",
        CR_INVALID_DEVICE_ID => "CR_INVALID_DEVICE_ID",
        CR_NO_SUCH_DEVINST => "CR_NO_SUCH_DEVINST",
        CR_NO_MORE_LOG_CONF => "CR_NO_MORE_LOG_CONF",
        CR_NO_MORE_RES_DES => "CR_NO_MORE_RES_DES",
        CR_ALREADY_SUCH_DEVINST => "CR_ALREADY_SUCH_DEVINST",
        CR_INVALID_RANGE_LIST => "CR_INVALID_RANGE_LIST",
        CR_INVALID_RANGE => "CR_INVALID_RANGE",
        CR_FAILURE => "CR_FAILURE",
        CR_NO_SUCH_LOGICAL_DEV => "CR_NO_SUCH_LOGICAL_DEV",
        CR_CREATE_BLOCKED => "CR_CREATE_BLOCKED",
        CR_NOT_SYSTEM_VM => "CR_NOT_SYSTEM_VM",
        CR_REMOVE_VETOED => "CR_REMOVE_VETOED",
        CR_APM_VETOED => "CR_APM_VETOED",
        CR_INVALID_LOAD_TYPE => "CR_INVALID_LOAD_TYPE",
        CR_BUFFER_SMALL => "CR_BUFFER_SMALL",
        CR_NO_ARBITRATOR => "CR_NO_ARBITRATOR",
        CR_REGISTRY_ERROR => "CR_REGISTRY_ERROR",
        CR_INVALID_DATA => "CR_INVALID_DATA",
        CR_INVALID_API => "CR_INVALID_API",
        CR_DEVLOADER_NOT_READY => "CR_DEVLOADER_NOT_READY",
        CR_NEED_RESTART => "CR_NEED_RESTART",
        CR_NO_MORE_HW_PROFILES => "CR_NO_MORE_HW_PROFILES",
        CR_DEVICE_NOT_THERE => "CR_DEVICE_NOT_THERE",
        CR_NO_SUCH_VALUE => "CR_NO_SUCH_VALUE",
        CR_WRONG_TYPE => "CR_WRONG_TYPE",
        CR_INVALID_PRIORITY => "CR_INVALID_PRIORITY",
        CR_NOT_DISABLEABLE => "CR_NOT_DISABLEABLE",
        CR_FREE_RESOURCES => "CR_FREE_RESOURCES",
        CR_QUERY_VETOED => "CR_QUERY_VETOED",
        CR_CANT_SHARE_IRQ => "CR_CANT_SHARE_IRQ",
        CR_NO_DEPENDENT => "CR_NO_DEPENDENT",
        CR_SAME_RESOURCES => "CR_SAME_RESOURCES",
        CR_NO_SUCH_REGISTRY_KEY => "CR_NO_SUCH_REGISTRY_KEY",
        CR_INVALID_MACHINENAME => "CR_INVALID_MACHINENAME",
        CR_REMOTE_COMM_FAILURE => "CR_REMOTE_COMM_FAILURE",
        CR_MACHINE_UNAVAILABLE => "CR_MACHINE_UNAVAILABLE",
        CR_NO_CM_SERVICES => "CR_NO_CM_SERVICES",
        CR_ACCESS_DENIED => "CR_ACCESS_DENIED",
        CR_CALL_NOT_IMPLEMENTED => "CR_CALL_NOT_IMPLEMENTED",
        CR_INVALID_PROPERTY => "CR_INVALID_PROPERTY",
        CR_DEVICE_INTERFACE_ACTIVE => "CR_DEVICE_INTERFACE_ACTIVE",
        CR_NO_SUCH_DEVICE_INTERFACE => "CR_NO_SUCH_DEVICE_INTERFACE",
        CR_INVALID_REFERENCE_STRING => "CR_INVALID_REFERENCE_STRING",
        CR_INVALID_CONFLICT_LIST => "CR_INVALID_CONFLICT_LIST",
        CR_INVALID_INDEX => "CR_INVALID_INDEX",
        CR_INVALID_STRUCTURE_SIZE => "CR_INVALID_STRUCTURE_SIZE",
        _ => "CR_UNKNOWN",
    }
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
    let key_path = startup_blob_registry_subkey(service_name);
    let encoded = blob
        .to_bytes()
        .context("failed to encode startup config")?;

    debug!(
        service_name,
        bytes = encoded.len(),
        "writing startup blob to registry"
    );

    let key = RegistryKey::create_local_machine_subkey(
        &key_path,
        KEY_CREATE_SUB_KEY | KEY_SET_VALUE,
    )?;
    key.set_binary_value(STARTUP_VALUE_NAME, &encoded)?;

    info!(service_name, "startup blob written to registry");
    Ok(())
}

pub fn read_startup_blob(service_name: &str) -> Result<Option<StartupConfig>, BoxError> {
    let key_path = startup_blob_registry_subkey(service_name);
    debug!(service_name, "reading startup blob from registry");
    let Some(key) = RegistryKey::open_local_machine_subkey(&key_path, KEY_QUERY_VALUE)? else {
        debug!(service_name, "startup blob registry key is not present");
        return Ok(None);
    };
    let Some(bytes) = key.query_binary_value(STARTUP_VALUE_NAME)? else {
        debug!(service_name, "startup blob is not present in registry");
        return Ok(None);
    };

    let blob = StartupConfig::from_bytes(&bytes)
        .ok_or_else(|| "failed to decode startup config blob".to_string())?;
    Ok(Some(blob))
}

pub fn sync_startup_blob(
    service_name: &str,
    ipv4_proxy: Option<(SocketAddrV4, u32)>,
    ipv6_proxy: Option<Option<(SocketAddrV6, u32)>>,
) -> Result<(), BoxError> {
    let current = read_startup_blob(service_name)?;

    let next_ipv4 = match ipv4_proxy {
        Some(ipv4) => ipv4,
        None => match current.as_ref() {
            Some(blob) => (blob.proxy_ipv4(), blob.proxy_ipv4_pid()),
            None => {
                return Err(BoxError::from(
                    "cannot update persisted startup config without an existing IPv4 proxy; use `enable` or pass `--ipv4-proxy`"
                ))
            }
        },
    };

    let next_ipv6 = match ipv6_proxy {
        Some(next) => next,
        None => current.and_then(|blob| blob.proxy_ipv6().zip(blob.proxy_ipv6_pid())),
    };

    write_startup_blob(service_name, &StartupConfig::new(next_ipv4.0, next_ipv4.1, next_ipv6))
}

pub fn delete_startup_blob(service_name: &str) -> Result<(), BoxError> {
    let key_path = startup_blob_registry_subkey(service_name);
    debug!(service_name, "deleting startup blob from registry");
    let Some(key) = RegistryKey::open_local_machine_subkey(&key_path, KEY_SET_VALUE)? else {
        debug!(service_name, "startup blob registry key was already absent");
        return Ok(());
    };

    if key.delete_value(STARTUP_VALUE_NAME)? {
        info!(service_name, "startup blob deleted from registry");
    } else {
        debug!(service_name, "startup blob was already absent");
    }
    Ok(())
}

struct RegistryKey(HKEY);

impl RegistryKey {
    fn create_local_machine_subkey(subkey: &str, desired_access: u32) -> Result<Self, BoxError> {
        let wide_subkey = to_wide(subkey);
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            // SAFETY: pointers are valid and output handle is writable.
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide_subkey.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                desired_access,
                ptr::null(),
                &mut handle,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(
                BoxError::from("failed to create/open registry key")
                    .context_str_field("subkey", subkey)
                    .context_field("win32", status),
            );
        }

        Ok(Self(handle))
    }

    fn open_local_machine_subkey(subkey: &str, desired_access: u32) -> Result<Option<Self>, BoxError> {
        let wide_subkey = to_wide(subkey);
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            // SAFETY: pointers are valid and output handle is writable.
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide_subkey.as_ptr(),
                0,
                desired_access,
                &mut handle,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(
                BoxError::from("failed to open registry key")
                    .context_str_field("subkey", subkey)
                    .context_field("win32", status),
            );
        }

        Ok(Some(Self(handle)))
    }

    fn set_binary_value(&self, value_name: &str, data: &[u8]) -> Result<(), BoxError> {
        let wide_name = to_wide(value_name);
        let status = unsafe {
            // SAFETY: handle is valid, value name is null-terminated, and data buffer is valid.
            RegSetValueExW(
                self.0,
                wide_name.as_ptr(),
                0,
                REG_BINARY,
                data.as_ptr(),
                data.len() as u32,
            )
        };
        if status != 0 {
            return Err(
                BoxError::from("failed to write registry value")
                    .context_str_field("name", value_name)
                    .context_field("win32", status),
            );
        }
        Ok(())
    }

    fn query_binary_value(&self, value_name: &str) -> Result<Option<Vec<u8>>, BoxError> {
        let wide_name = to_wide(value_name);
        let mut value_type = 0;
        let mut data_len = 0;
        let status = unsafe {
            // SAFETY: handle is valid and output pointers are writable.
            RegQueryValueExW(
                self.0,
                wide_name.as_ptr(),
                ptr::null(),
                &mut value_type,
                null_mut(),
                &mut data_len,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(
                BoxError::from("failed to query registry value size")
                    .context_str_field("name", value_name)
                    .context_field("win32", status),
            );
        }
        if value_type != REG_BINARY {
            return Err(
                BoxError::from("registry value has unexpected type")
                    .context_str_field("name", value_name)
                    .context_field("registry_type", value_type),
            );
        }

        let mut data = vec![0_u8; data_len as usize];
        let status = unsafe {
            // SAFETY: handle is valid and the output buffer is sized from the queried length.
            RegQueryValueExW(
                self.0,
                wide_name.as_ptr(),
                ptr::null(),
                &mut value_type,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if status != 0 {
            return Err(
                BoxError::from("failed to read registry value")
                    .context_str_field("name", value_name)
                    .context_field("win32", status),
            );
        }
        if value_type != REG_BINARY {
            return Err(
                BoxError::from("registry value has unexpected type")
                    .context_str_field("name", value_name)
                    .context_field("registry_type", value_type),
            );
        }

        data.truncate(data_len as usize);
        Ok(Some(data))
    }

    fn delete_value(&self, value_name: &str) -> Result<bool, BoxError> {
        let wide_name = to_wide(value_name);
        let status = unsafe {
            // SAFETY: handle is valid and value name is null-terminated.
            RegDeleteValueW(self.0, wide_name.as_ptr())
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        if status != 0 {
            return Err(
                BoxError::from("failed to delete registry value")
                    .context_str_field("name", value_name)
                    .context_field("win32", status),
            );
        }
        Ok(true)
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: handle belongs to this wrapper and is closed exactly once here.
                RegCloseKey(self.0);
            }
        }
    }
}

fn startup_blob_registry_subkey(service_name: &str) -> String {
    format!(r"SYSTEM\CurrentControlSet\Services\{service_name}\Parameters")
}

fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
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
