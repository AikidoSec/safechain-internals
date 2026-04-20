use alloc::string::String;
use core::ptr;

use wdk_sys::{
    HANDLE, PEPROCESS, PUNICODE_STRING, STATUS_SUCCESS,
    ntddk::{
        ExFreePool, ObfDereferenceObject, PsLookupProcessByProcessId, SeLocateProcessImageName,
    },
};

use crate::log;

use super::ffi::{FWPS_INCOMING_METADATA_VALUES0, FWPS_METADATA_FIELD_PROCESS_ID};
use safechain_proxy_lib_nostd::windows::unicode::unicode_string_to_string;

pub(crate) fn source_pid_from_metadata(
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
) -> Option<u32> {
    let metadata = incoming_metadata_values(in_meta_values)?;
    let raw_pid = unsafe {
        // SAFETY: the metadata pointer is valid for this classify callback.
        if ((*metadata).currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0 {
            return None;
        }
        (*metadata).processId
    };
    u32::try_from(raw_pid).ok()
}

pub(crate) fn source_process_path_from_pid(pid: u32) -> Option<String> {
    let mut process: PEPROCESS = ptr::null_mut();
    let status = unsafe {
        // SAFETY: PID is reinterpreted as the HANDLE form expected by the kernel API.
        PsLookupProcessByProcessId(pid_to_handle(pid), &mut process)
    };
    if status != STATUS_SUCCESS || process.is_null() {
        log::driver_log_warn!(
            "wfp: failed to resolve process object from pid (pid = {}, status = {:#x})",
            pid,
            status
        );
        return None;
    }

    let mut image_name: PUNICODE_STRING = ptr::null_mut();

    unsafe {
        // SAFETY: `process` is referenced by `PsLookupProcessByProcessId` above.
        let status = SeLocateProcessImageName(process, &mut image_name);
        let _ = ObfDereferenceObject(process.cast());

        if status != STATUS_SUCCESS || image_name.is_null() {
            log::driver_log_warn!(
                "wfp: failed to resolve process image path from pid (pid = {}, status = {:#x})",
                pid,
                status
            );
            None
        } else {
            let path = unicode_string_to_string(image_name.cast_const());
            ExFreePool(image_name.cast());
            path
        }
    }
}

fn pid_to_handle(pid: u32) -> HANDLE {
    pid as usize as HANDLE
}

pub(crate) fn incoming_metadata_values(
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
) -> Option<*const FWPS_INCOMING_METADATA_VALUES0> {
    if in_meta_values.is_null() {
        return None;
    }
    Some(in_meta_values.cast::<FWPS_INCOMING_METADATA_VALUES0>())
}
