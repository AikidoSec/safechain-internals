use alloc::{string::String, vec::Vec};
use core::{iter, mem::size_of, slice};

use wdk_sys::{PCUNICODE_STRING, UNICODE_STRING};

pub fn utf16_null_terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(iter::once(0)).collect()
}

pub fn unicode_from_wide_mut(wide: &mut [u16]) -> UNICODE_STRING {
    let max_len_bytes = core::mem::size_of_val(wide);
    let len_bytes = max_len_bytes.saturating_sub(size_of::<u16>());
    UNICODE_STRING {
        Length: len_bytes as u16,
        MaximumLength: max_len_bytes as u16,
        Buffer: wide.as_mut_ptr(),
    }
}

/// Convert a kernel `UNICODE_STRING` into an owned Rust `String`.
///
/// # Safety
/// Caller must guarantee the pointer is valid for reads for the duration of the call.
pub unsafe fn unicode_string_to_string(unicode: PCUNICODE_STRING) -> Option<String> {
    let unicode = unsafe {
        // SAFETY: guaranteed by the caller.
        unicode.as_ref()?
    };
    let buffer = unicode.Buffer;
    if buffer.is_null() || unicode.Length == 0 {
        return None;
    }

    let utf16_len = usize::from(unicode.Length) / 2;
    let utf16 = unsafe {
        // SAFETY: guaranteed by the caller and bounded by the UNICODE_STRING length.
        slice::from_raw_parts(buffer, utf16_len)
    };
    Some(String::from_utf16_lossy(utf16))
}
