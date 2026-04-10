use core::{iter, mem::size_of, ptr};
use wdk_sys::{
    KEY_READ, OBJ_CASE_INSENSITIVE, OBJECT_ATTRIBUTES, PCUNICODE_STRING, REG_BINARY,
    STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS, UNICODE_STRING,
    ntddk::{ZwClose, ZwOpenKey, ZwQueryValueKey},
};

use super::*;

const KEY_VALUE_PARTIAL_INFORMATION_CLASS: i32 = 2;
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

pub fn load_startup_config(registry_path: PCUNICODE_STRING) -> Option<ProxyDriverStartupConfig> {
    let blob = read_startup_blob_from_registry(registry_path)?;
    parse_startup_blob(&blob)
}

pub fn parse_startup_blob(blob: &[u8]) -> Option<ProxyDriverStartupConfig> {
    let decoded = StartupConfig::from_bytes(blob)?;

    Some(ProxyDriverStartupConfig {
        proxy_ipv4: decoded.proxy_ipv4(),
        proxy_ipv6: decoded.proxy_ipv6(),
    })
}

fn read_startup_blob_from_registry(registry_path: PCUNICODE_STRING) -> Option<alloc::vec::Vec<u8>> {
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
    let close_status = unsafe {
        // SAFETY: handle returned by ZwOpenKey must be closed once no longer needed.
        ZwClose(key_handle)
    };
    if close_status != STATUS_SUCCESS {
        return None;
    }
    result
}

fn query_startup_value_blob(key_handle: *mut core::ffi::c_void) -> Option<alloc::vec::Vec<u8>> {
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

    let mut buffer = alloc::vec![0_u8; needed_len as usize];
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
    if buffer.len() < header_len + data_len {
        return None;
    }

    Some(buffer[header_len..header_len + data_len].to_vec())
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
        let v = slice.to_vec();
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
    let max_len_bytes = core::mem::size_of_val(wide);
    let len_bytes = max_len_bytes.saturating_sub(size_of::<u16>());
    UNICODE_STRING {
        Length: len_bytes as u16,
        MaximumLength: max_len_bytes as u16,
        Buffer: wide.as_mut_ptr(),
    }
}

#[cfg(test)]
#[path = "startup_config_tests.rs"]
mod tests;
