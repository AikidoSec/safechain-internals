use core::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use wdk_sys::{NTSTATUS, PCUNICODE_STRING, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

use crate::driver::{ProxyDriverConfigUpdate, ProxyDriverController, ProxyDriverStartupConfig};

pub fn initialize_startup_config(
    controller: &ProxyDriverController,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let Some(startup_config) = startup_config::load_startup_config(registry_path) else {
        return STATUS_INVALID_PARAMETER;
    };

    if controller.apply_startup_config(startup_config) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

pub fn apply_runtime_update(
    controller: &ProxyDriverController,
    update: ProxyDriverConfigUpdate,
) -> NTSTATUS {
    if controller.apply_runtime_update(update) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

pub mod ioctl {
    use super::*;

    const FILE_DEVICE_SAFECHAIN_PROXY: u32 = 0x8000;
    const FILE_ANY_ACCESS: u32 = 0;
    const METHOD_BUFFERED: u32 = 0;

    pub const IOCTL_SET_IPV4_PROXY: u32 = ctl_code(
        FILE_DEVICE_SAFECHAIN_PROXY,
        0x801,
        METHOD_BUFFERED,
        FILE_ANY_ACCESS,
    );
    pub const IOCTL_SET_IPV6_PROXY: u32 = ctl_code(
        FILE_DEVICE_SAFECHAIN_PROXY,
        0x802,
        METHOD_BUFFERED,
        FILE_ANY_ACCESS,
    );
    pub const IOCTL_CLEAR_IPV6_PROXY: u32 = ctl_code(
        FILE_DEVICE_SAFECHAIN_PROXY,
        0x803,
        METHOD_BUFFERED,
        FILE_ANY_ACCESS,
    );

    pub fn handle_device_control_ioctl(
        controller: &ProxyDriverController,
        ioctl_code: u32,
        input: &[u8],
    ) -> (NTSTATUS, usize) {
        let update = match ioctl_code {
            IOCTL_SET_IPV4_PROXY => parse_ipv4_update(input),
            IOCTL_SET_IPV6_PROXY => parse_ipv6_update(input),
            IOCTL_CLEAR_IPV6_PROXY => Some(ProxyDriverConfigUpdate::SetIpv6(None)),
            _ => None,
        };

        let Some(update) = update else {
            return (STATUS_INVALID_PARAMETER, 0);
        };

        let status = super::apply_runtime_update(controller, update);
        (status, 0)
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Ipv4ProxyConfigPayload {
        ip_be: [u8; 4],
        port_be: u16,
        _reserved: u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Ipv6ProxyConfigPayload {
        ip_be: [u8; 16],
        port_be: u16,
        _reserved: u16,
    }

    fn parse_ipv4_update(input: &[u8]) -> Option<ProxyDriverConfigUpdate> {
        if input.len() != size_of::<Ipv4ProxyConfigPayload>() {
            return None;
        }

        // SAFETY: exact-size slice copy into a POD payload struct.
        let payload = unsafe { (input.as_ptr() as *const Ipv4ProxyConfigPayload).read_unaligned() };
        let addr = Ipv4Addr::from(payload.ip_be);
        let port = u16::from_be(payload.port_be);
        Some(ProxyDriverConfigUpdate::SetIpv4(SocketAddr::new(
            IpAddr::V4(addr),
            port,
        )))
    }

    fn parse_ipv6_update(input: &[u8]) -> Option<ProxyDriverConfigUpdate> {
        if input.len() != size_of::<Ipv6ProxyConfigPayload>() {
            return None;
        }

        // SAFETY: exact-size slice copy into a POD payload struct.
        let payload = unsafe { (input.as_ptr() as *const Ipv6ProxyConfigPayload).read_unaligned() };
        let addr = Ipv6Addr::from(payload.ip_be);
        let port = u16::from_be(payload.port_be);
        Some(ProxyDriverConfigUpdate::SetIpv6(Some(SocketAddr::new(
            IpAddr::V6(addr),
            port,
        ))))
    }

    const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::driver::ProxyDriverController;
        use core::net::{IpAddr, Ipv4Addr, SocketAddr};

        #[test]
        fn parse_and_apply_ipv4_update() {
            let controller = ProxyDriverController::new();
            let payload = Ipv4ProxyConfigPayload {
                ip_be: [127, 0, 0, 1],
                port_be: 15_000_u16.to_be(),
                _reserved: 0,
            };
            let input = {
                let ptr = &payload as *const Ipv4ProxyConfigPayload as *const u8;
                // SAFETY: payload pointer and length are valid for read-only byte view.
                unsafe { core::slice::from_raw_parts(ptr, size_of::<Ipv4ProxyConfigPayload>()) }
            };

            let (status, _) = handle_device_control_ioctl(&controller, IOCTL_SET_IPV4_PROXY, input);
            assert_eq!(status, STATUS_SUCCESS);
            assert!(
                controller
                    .proxy_endpoint_for(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443))
                    .is_some()
            );
        }
    }
}

pub mod startup_config {
    use super::*;
    use alloc::vec;
    use core::{iter, mem::size_of, ptr};
    use wdk_sys::{
        KEY_READ, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJECT_ATTRIBUTES, PCUNICODE_STRING, REG_BINARY,
        STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS, UNICODE_STRING,
        ntddk::{ZwClose, ZwOpenKey, ZwQueryValueKey},
    };

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct StartupConfigBlobV1 {
        magic: [u8; 4],
        version_be: u16,
        flags_be: u16,
        ipv4_be: [u8; 4],
        ipv4_port_be: u16,
        _reserved0: u16,
        ipv6_be: [u8; 16],
        ipv6_port_be: u16,
        _reserved1: u16,
    }

    const STARTUP_BLOB_MAGIC: [u8; 4] = *b"SCL4";
    const STARTUP_BLOB_VERSION_V1: u16 = 1;
    const STARTUP_FLAG_IPV6_PRESENT: u16 = 1 << 0;
    const KEY_VALUE_PARTIAL_INFORMATION_CLASS: i32 = 2;
    const STARTUP_VALUE_NAME: &str = "ProxyStartupConfigV1";
    const PARAMETERS_SUFFIX: &str = "\\Parameters";

    #[repr(C)]
    /// Prefix of `KEY_VALUE_PARTIAL_INFORMATION` used by `ZwQueryValueKey`.
    ///
    /// Official docs:
    /// - `ZwQueryValueKey`:
    ///   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryvaluekey
    /// - `KEY_VALUE_PARTIAL_INFORMATION`:
    ///   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_partial_information
    struct KeyValuePartialInformationPrefix {
        _title_index: u32,
        value_type: u32,
        data_length: u32,
    }

    pub fn load_startup_config(
        registry_path: PCUNICODE_STRING,
    ) -> Option<ProxyDriverStartupConfig> {
        let blob = read_startup_blob_from_registry(registry_path)?;
        parse_startup_blob(&blob)
    }

    pub fn parse_startup_blob(blob: &[u8]) -> Option<ProxyDriverStartupConfig> {
        if blob.len() != size_of::<StartupConfigBlobV1>() {
            return None;
        }

        // SAFETY: exact-size slice copy into a POD payload struct.
        let decoded = unsafe { (blob.as_ptr() as *const StartupConfigBlobV1).read_unaligned() };
        if decoded.magic != STARTUP_BLOB_MAGIC {
            return None;
        }
        if u16::from_be(decoded.version_be) != STARTUP_BLOB_VERSION_V1 {
            return None;
        }

        let ipv4 = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(decoded.ipv4_be)),
            u16::from_be(decoded.ipv4_port_be),
        );

        let flags = u16::from_be(decoded.flags_be);
        let ipv6 = if flags & STARTUP_FLAG_IPV6_PRESENT != 0 {
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(decoded.ipv6_be)),
                u16::from_be(decoded.ipv6_port_be),
            ))
        } else {
            None
        };

        Some(ProxyDriverStartupConfig {
            proxy_ipv4: ipv4,
            proxy_ipv6: ipv6,
        })
    }

    fn read_startup_blob_from_registry(
        registry_path: PCUNICODE_STRING,
    ) -> Option<[u8; size_of::<StartupConfigBlobV1>()]> {
        let mut parameters_path = registry_path_to_parameters_path(registry_path)?;
        let mut parameters_path_us = unicode_from_wide_mut(&mut parameters_path);

        let mut object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: &mut parameters_path_us,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };

        let mut key_handle = ptr::null_mut();
        let open_status = unsafe {
            // SAFETY: OBJECT_ATTRIBUTES points to valid and initialized objects.
            ZwOpenKey(&mut key_handle, KEY_READ, &mut object_attributes)
        };
        if open_status != STATUS_SUCCESS {
            return None;
        }

        let result = query_startup_value_blob(key_handle);
        unsafe {
            // SAFETY: handle returned by ZwOpenKey must be closed once no longer needed.
            ZwClose(key_handle);
        }
        result
    }

    fn query_startup_value_blob(
        key_handle: *mut core::ffi::c_void,
    ) -> Option<[u8; size_of::<StartupConfigBlobV1>()]> {
        let mut value_name_w = utf16_null_terminated(STARTUP_VALUE_NAME);
        let mut value_name_us = unicode_from_wide_mut(&mut value_name_w);

        let mut needed_len: u32 = 0;
        let initial_status = unsafe {
            // SAFETY: value name and key handle are valid; output length pointer is valid.
            ZwQueryValueKey(
                key_handle,
                &mut value_name_us,
                KEY_VALUE_PARTIAL_INFORMATION_CLASS,
                ptr::null_mut(),
                0,
                &mut needed_len,
            )
        };
        if initial_status != STATUS_BUFFER_TOO_SMALL && initial_status != STATUS_BUFFER_OVERFLOW {
            return None;
        }
        if needed_len < size_of::<KeyValuePartialInformationPrefix>() as u32 {
            return None;
        }

        let mut buffer = vec![0_u8; needed_len as usize];
        let mut out_len: u32 = needed_len;
        let query_status = unsafe {
            // SAFETY: output buffer is valid for out_len bytes.
            ZwQueryValueKey(
                key_handle,
                &mut value_name_us,
                KEY_VALUE_PARTIAL_INFORMATION_CLASS,
                buffer.as_mut_ptr().cast(),
                out_len,
                &mut out_len,
            )
        };
        if query_status != STATUS_SUCCESS {
            return None;
        }
        if out_len < size_of::<KeyValuePartialInformationPrefix>() as u32 {
            return None;
        }

        let prefix = unsafe {
            // SAFETY: buffer length checked to include the prefix bytes.
            &*(buffer.as_ptr().cast::<KeyValuePartialInformationPrefix>())
        };
        if prefix.value_type != REG_BINARY {
            return None;
        }

        let header_len = size_of::<KeyValuePartialInformationPrefix>();
        let data_len = prefix.data_length as usize;
        if data_len != size_of::<StartupConfigBlobV1>() {
            return None;
        }
        if buffer.len() < header_len + data_len {
            return None;
        }

        let mut blob = [0_u8; size_of::<StartupConfigBlobV1>()];
        blob.copy_from_slice(&buffer[header_len..header_len + data_len]);
        Some(blob)
    }

    fn registry_path_to_parameters_path(
        registry_path: PCUNICODE_STRING,
    ) -> Option<alloc::vec::Vec<u16>> {
        if registry_path.is_null() {
            return None;
        }
        let (mut path, had_nul) = unsafe {
            // SAFETY: pointer comes from DriverEntry contract and Length bounds are trusted kernel input.
            let us = &*registry_path;
            if us.Buffer.is_null() || us.Length == 0 {
                return None;
            }
            let units = (us.Length as usize) / size_of::<u16>();
            let slice = core::slice::from_raw_parts(us.Buffer, units);
            let mut v = slice.to_vec();
            let had_nul = v.last().copied() == Some(0);
            (v, had_nul)
        };

        if !had_nul {
            path.push(0);
        }
        if path.last().copied() == Some(0) {
            path.pop();
        }
        path.extend(PARAMETERS_SUFFIX.encode_utf16());
        path.push(0);
        Some(path)
    }

    fn utf16_null_terminated(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().chain(iter::once(0)).collect()
    }

    fn unicode_from_wide_mut(wide: &mut [u16]) -> UNICODE_STRING {
        let max_len_bytes = wide.len() * size_of::<u16>();
        let len_bytes = max_len_bytes.saturating_sub(size_of::<u16>());
        UNICODE_STRING {
            Length: len_bytes as u16,
            MaximumLength: max_len_bytes as u16,
            Buffer: wide.as_mut_ptr(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_blob_with_optional_ipv6_absent() {
            let blob = StartupConfigBlobV1 {
                magic: STARTUP_BLOB_MAGIC,
                version_be: STARTUP_BLOB_VERSION_V1.to_be(),
                flags_be: 0_u16.to_be(),
                ipv4_be: [127, 0, 0, 1],
                ipv4_port_be: 15000_u16.to_be(),
                _reserved0: 0,
                ipv6_be: [0; 16],
                ipv6_port_be: 0,
                _reserved1: 0,
            };
            let bytes = {
                let ptr = &blob as *const StartupConfigBlobV1 as *const u8;
                // SAFETY: blob pointer and length are valid for read-only byte view.
                unsafe { core::slice::from_raw_parts(ptr, size_of::<StartupConfigBlobV1>()) }
            };
            let parsed = parse_startup_blob(bytes).expect("blob should parse");
            assert!(matches!(parsed.proxy_ipv4, SocketAddr::V4(_)));
            assert!(parsed.proxy_ipv6.is_none());
        }
    }
}
