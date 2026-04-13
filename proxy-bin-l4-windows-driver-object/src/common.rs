use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    ptr::{self, null_mut},
    thread,
    time::Duration,
};

use rama_core::{
    error::{BoxError, ErrorExt as _},
    telemetry::tracing::{debug, info, warn},
};
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::{
        CM_DISABLE_ABSOLUTE, CM_DISABLE_PERSIST, CM_DISABLE_UI_NOT_OK, CM_Disable_DevNode,
        CM_Enable_DevNode, CM_Uninstall_DevNode, CR_ACCESS_DENIED, CR_ALREADY_SUCH_DEVINST,
        CR_APM_VETOED, CR_BUFFER_SMALL, CR_CALL_NOT_IMPLEMENTED, CR_CANT_SHARE_IRQ,
        CR_CREATE_BLOCKED, CR_DEFAULT, CR_DEVICE_INTERFACE_ACTIVE, CR_DEVICE_NOT_THERE,
        CR_DEVINST_HAS_REQS, CR_DEVLOADER_NOT_READY, CR_FAILURE, CR_FREE_RESOURCES, CR_INVALID_API,
        CR_INVALID_ARBITRATOR, CR_INVALID_CONFLICT_LIST, CR_INVALID_DATA, CR_INVALID_DEVICE_ID,
        CR_INVALID_DEVINST, CR_INVALID_FLAG, CR_INVALID_INDEX, CR_INVALID_LOAD_TYPE,
        CR_INVALID_LOG_CONF, CR_INVALID_MACHINENAME, CR_INVALID_NODELIST, CR_INVALID_POINTER,
        CR_INVALID_PRIORITY, CR_INVALID_PROPERTY, CR_INVALID_RANGE, CR_INVALID_RANGE_LIST,
        CR_INVALID_REFERENCE_STRING, CR_INVALID_RES_DES, CR_INVALID_RESOURCEID,
        CR_INVALID_STRUCTURE_SIZE, CR_MACHINE_UNAVAILABLE, CR_NEED_RESTART, CR_NO_ARBITRATOR,
        CR_NO_CM_SERVICES, CR_NO_DEPENDENT, CR_NO_MORE_HW_PROFILES, CR_NO_MORE_LOG_CONF,
        CR_NO_MORE_RES_DES, CR_NO_SUCH_DEVICE_INTERFACE, CR_NO_SUCH_DEVINST,
        CR_NO_SUCH_LOGICAL_DEV, CR_NO_SUCH_REGISTRY_KEY, CR_NO_SUCH_VALUE, CR_NOT_DISABLEABLE,
        CR_NOT_SYSTEM_VM, CR_OUT_OF_MEMORY, CR_QUERY_VETOED, CR_REGISTRY_ERROR,
        CR_REMOTE_COMM_FAILURE, CR_REMOVE_VETOED, CR_SAME_RESOURCES, CR_SUCCESS, CR_WRONG_TYPE,
        DIGCF_ALLCLASSES, HDEVINFO, SP_DEVINFO_DATA, SPDRP_SERVICE, SetupDiDestroyDeviceInfoList,
        SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
        SetupDiGetDeviceRegistryPropertyW,
    },
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};

pub use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY, IOCTL_SET_IPV6_PROXY, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload,
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
            return Err(BoxError::from("failed to enable device")
                .context_str_field("name", service_name)
                .context_str_field("instance_id", &device.instance_id)
                .context_field("cfgmgr32", cr));
        }

        info!(service_name, instance_id = %device.instance_id, "device enabled successfully");
    }

    Ok(())
}

pub fn disable_device(service_name: &str, force_remove_on_veto: bool) -> Result<(), BoxError> {
    debug!(service_name, "disabling device via PnP");
    let devices = find_devices_for_service(service_name)?;
    if devices.is_empty() {
        info!(
            service_name,
            "no matching PnP device found; treating disable as already complete"
        );
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
            return Err(BoxError::from("failed to disable device")
                .context_str_field("name", service_name)
                .context_str_field("instance_id", &device.instance_id)
                .context_field("cfgmgr32", cr)
                .context_str_field("cfgmgr32_name", configret_name(cr)));
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
            SetupDiGetClassDevsW(
                ptr::null(),
                ptr::null(),
                std::ptr::null_mut(),
                DIGCF_ALLCLASSES,
            )
        };
        if handle == INVALID_HANDLE_VALUE as isize {
            return Err(BoxError::from("failed to enumerate device info set")
                .context_field("win32", unsafe { GetLastError() }));
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

            return Err(BoxError::from("failed to enumerate devices")
                .context_str_field("name", service_name)
                .context_field("win32", code));
        }

        let Some(device_service_name) = query_device_service_name(device_info_set.0, &device_info)?
        else {
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
        return Err(BoxError::from(
            "unexpected success while probing device registry property size",
        )
        .context_field("property", property));
    }

    let code = unsafe { GetLastError() };
    if code == ERROR_INVALID_DATA {
        return Ok(None);
    }
    if code != ERROR_INSUFFICIENT_BUFFER || required_size == 0 {
        return Err(BoxError::from("failed to query device registry property")
            .context_field("property", property)
            .context_field("win32", code));
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
        return Err(BoxError::from("failed to read device registry property")
            .context_field("property", property)
            .context_field("win32", unsafe { GetLastError() }));
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
        SetupDiGetDeviceInstanceIdW(
            device_info_set,
            device_info,
            null_mut(),
            0,
            &mut required_size,
        )
    };
    if ok != 0 {
        return Err(BoxError::from(
            "unexpected success while probing device instance id size",
        ));
    }

    let code = unsafe { GetLastError() };
    if code != ERROR_INSUFFICIENT_BUFFER || required_size == 0 {
        return Err(
            BoxError::from("failed to query device instance id size").context_field("win32", code)
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
        return Err(BoxError::from("failed to read device instance id")
            .context_field("win32", unsafe { GetLastError() }));
    }

    Ok(from_wide_with_nul(&buffer))
}

fn from_wide_with_nul(value: &[u16]) -> String {
    let end = value.iter().position(|&ch| ch == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
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
            return Err(BoxError::from("failed to open device")
                .context_str_field("device_path", device_path)
                .context_field("win32", unsafe { GetLastError() }));
        }

        info!(device_path, "opened driver device handle");
        Ok(Self(handle))
    }

    pub fn open_with_retry(
        device_path: &str,
        attempts: usize,
        retry_delay: Duration,
    ) -> Result<Self, BoxError> {
        let attempts = attempts.max(1);
        let mut last_error = None;

        for attempt in 1..=attempts {
            match Self::open(device_path) {
                Ok(handle) => {
                    if attempt > 1 {
                        info!(
                            device_path,
                            attempt, "opened driver device handle after retry"
                        );
                    }
                    return Ok(handle);
                }
                Err(err) => {
                    last_error = Some(err);
                    if attempt < attempts {
                        warn!(
                            device_path,
                            attempt,
                            retry_delay_ms = retry_delay.as_millis(),
                            "opening driver device handle failed; retrying"
                        );
                        thread::sleep(retry_delay);
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            BoxError::from("failed to open device after retry")
                .context_str_field("device_path", device_path)
        }))
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
            return Err(BoxError::from("DeviceIoControl failed for ioctl")
                .context_hex_field("ioctl", ioctl)
                .context_field("win32", unsafe { GetLastError() }));
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
