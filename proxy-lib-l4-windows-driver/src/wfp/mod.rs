//! Windows Filtering Platform (WFP) kernel callout integration.
//!
//! This module intentionally keeps a very small owned FFI surface so we are not
//! blocked by third-party wrappers and can audit every unsafe boundary.
//!
//! Official references (WDK / Microsoft Learn):
//! - `FWPS_CALLOUT_CLASSIFY_FN1`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn1
//! - `FWPS_CONNECT_REQUEST0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0
//! - `FwpsAcquireWritableLayerDataPointer0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
//! - `FwpsApplyModifiedLayerData0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
//! - `FWPS_CONNECT_REQUEST0.localRedirectContext` ownership:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0
//! - `FwpsRedirectHandleCreate0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsredirecthandlecreate0
//! - `FwpsQueryConnectionRedirectState0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
//! - `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-records

use alloc::{string::String, vec::Vec};
use core::{ffi::c_void, net::SocketAddr, ptr};

mod classify;
mod ffi;
mod metadata;
mod sockaddr;

use safechain_proxy_lib_nostd::{
    net::is_passthrough_ip, windows::redirect_ctx::ProxyRedirectContext,
};
use spin::Mutex;
use wdk_sys::{NTSTATUS, STATUS_SUCCESS};

use crate::log;
use classify::on_callout_classify;
use ffi::{
    ExAllocatePoolWithTag, FWPS_CALLOUT1, FWPS_FILTER1, FwpsCalloutRegister1,
    FwpsCalloutUnregisterByKey0, FwpsRedirectHandleCreate0, FwpsRedirectHandleDestroy0, GUID,
    GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4, GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
    GUID_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4,
    GUID_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6, GUID_PROVIDER_SAFECHAIN_L4_PROXY,
    NON_PAGED_POOL, SAFECHAIN_POOL_TAG, STATUS_INVALID_PARAMETER,
};

/// Minimal flow metadata for an outbound TCP connect classification.
#[derive(Debug, Clone)]
pub struct WfpFlowMeta {
    pub remote: SocketAddr,
    pub source_pid: Option<u32>,
    pub source_process_path: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TcpRedirectDecision {
    Passthrough,
    Redirect {
        proxy_target: SocketAddr,
        proxy_target_pid: u32,
        redirect_context: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum UdpAuthConnectDecision {
    Passthrough,
    Block,
}

pub fn build_redirect_context(flow: &WfpFlowMeta) -> Result<Vec<u8>, postcard::Error> {
    let ctx = ProxyRedirectContext::new(flow.remote)
        .with_source_pid(flow.source_pid)
        .with_source_process_path(flow.source_process_path.clone());
    postcard::to_allocvec(&ctx)
}

#[inline(always)]
pub fn is_local_destination(destination: SocketAddr) -> bool {
    is_passthrough_ip(destination.ip())
}

#[derive(Clone, Copy)]
struct KernelCalloutRegistration {
    tcp_callout_id_v4: u32,
    tcp_callout_id_v6: Option<u32>,
    udp_callout_id_v4: u32,
    udp_callout_id_v6: Option<u32>,
    redirect_handle: usize,
}

static KERNEL_CALLOUT_REGISTRATION: Mutex<Option<KernelCalloutRegistration>> = Mutex::new(None);

const TCP_REDIRECT_V4: &GUID = &GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4;
const TCP_REDIRECT_V6: &GUID = &GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6;
const UDP_AUTH_CONNECT_BLOCK_V4: &GUID = &GUID_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4;
const UDP_AUTH_CONNECT_BLOCK_V6: &GUID = &GUID_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6;

pub fn register_callouts(device_object: *mut c_void) -> NTSTATUS {
    if device_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut registration = KERNEL_CALLOUT_REGISTRATION.lock();
    if registration.is_some() {
        return STATUS_SUCCESS;
    }

    let mut redirect_handle = ptr::null_mut();
    let redirect_status = unsafe {
        // SAFETY: output pointer is valid for the duration of the call.
        FwpsRedirectHandleCreate0(&GUID_PROVIDER_SAFECHAIN_L4_PROXY, 0, &mut redirect_handle)
    };
    if redirect_status != STATUS_SUCCESS {
        return redirect_status;
    }

    let mut tcp_callout_id_v4 = 0_u32;
    let status_v4 = register_callout(device_object, TCP_REDIRECT_V4, &mut tcp_callout_id_v4);
    if status_v4 != STATUS_SUCCESS {
        unsafe { FwpsRedirectHandleDestroy0(redirect_handle) };
        return status_v4;
    }

    let mut tcp_v6_id = 0_u32;
    let status_v6 = register_callout(device_object, TCP_REDIRECT_V6, &mut tcp_v6_id);
    if status_v6 != STATUS_SUCCESS {
        unsafe {
            unregister_callouts_by_key(&[TCP_REDIRECT_V4]);
            FwpsRedirectHandleDestroy0(redirect_handle);
        }
        return status_v6;
    }
    let tcp_callout_id_v6 = Some(tcp_v6_id);

    let mut udp_callout_id_v4 = 0_u32;
    let udp_status_v4 = register_callout(
        device_object,
        UDP_AUTH_CONNECT_BLOCK_V4,
        &mut udp_callout_id_v4,
    );
    if udp_status_v4 != STATUS_SUCCESS {
        unsafe {
            unregister_callouts_by_key(&[TCP_REDIRECT_V6, TCP_REDIRECT_V4]);
            FwpsRedirectHandleDestroy0(redirect_handle);
        }
        return udp_status_v4;
    }

    let mut udp_v6_id = 0_u32;
    let udp_status_v6 = register_callout(device_object, UDP_AUTH_CONNECT_BLOCK_V6, &mut udp_v6_id);
    if udp_status_v6 != STATUS_SUCCESS {
        unsafe {
            unregister_callouts_by_key(&[
                UDP_AUTH_CONNECT_BLOCK_V4,
                TCP_REDIRECT_V6,
                TCP_REDIRECT_V4,
            ]);
            FwpsRedirectHandleDestroy0(redirect_handle);
        }
        return udp_status_v6;
    }
    let udp_callout_id_v6 = Some(udp_v6_id);

    *registration = Some(KernelCalloutRegistration {
        tcp_callout_id_v4,
        tcp_callout_id_v6,
        udp_callout_id_v4,
        udp_callout_id_v6,
        redirect_handle: redirect_handle as usize,
    });

    log::driver_log_info!(
        "kernel callouts registered for tcp redirect and udp auth-connect block (tcp_v4_id={}, tcp_v6_id={:?}, udp_v4_id={}, udp_v6_id={:?})",
        tcp_callout_id_v4,
        tcp_callout_id_v6,
        udp_callout_id_v4,
        udp_callout_id_v6,
    );
    STATUS_SUCCESS
}

pub fn unregister_callouts() {
    let Some(reg) = KERNEL_CALLOUT_REGISTRATION.lock().take() else {
        return;
    };

    unsafe {
        if reg.udp_callout_id_v6.is_some() {
            unregister_callouts_by_key(&[UDP_AUTH_CONNECT_BLOCK_V6]);
        }
        unregister_callouts_by_key(&[UDP_AUTH_CONNECT_BLOCK_V4]);
        if reg.tcp_callout_id_v6.is_some() {
            unregister_callouts_by_key(&[TCP_REDIRECT_V6]);
        }
        unregister_callouts_by_key(&[TCP_REDIRECT_V4]);
        FwpsRedirectHandleDestroy0(reg.redirect_handle as *mut c_void);
    }

    log::driver_log_info!(
        "kernel callouts unregistered (tcp_v4_id={}, tcp_v6_id={:?}, udp_v4_id={}, udp_v6_id={:?})",
        reg.tcp_callout_id_v4,
        reg.tcp_callout_id_v6,
        reg.udp_callout_id_v4,
        reg.udp_callout_id_v6,
    );
}

unsafe extern "C" fn on_callout_notify(
    _notify_type: i32,
    _filter_key: *const GUID,
    _filter: *mut FWPS_FILTER1,
) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "C" fn on_callout_flow_delete(_layer_id: u16, _callout_id: u32, _flow_context: u64) {}

fn register_callout(
    device_object: *mut c_void,
    callout_key: &GUID,
    callout_id: &mut u32,
) -> NTSTATUS {
    let callout = FWPS_CALLOUT1 {
        calloutKey: *callout_key,
        flags: 0,
        classifyFn: Some(on_callout_classify),
        notifyFn: Some(on_callout_notify),
        flowDeleteFn: Some(on_callout_flow_delete),
    };

    unsafe { FwpsCalloutRegister1(device_object, &callout, callout_id) }
}

unsafe fn unregister_callouts_by_key(callout_keys: &[&GUID]) {
    for callout_key in callout_keys {
        let status = unsafe { FwpsCalloutUnregisterByKey0(*callout_key) };
        if status != STATUS_SUCCESS {
            log::driver_log_warn!("failed to unregister callout by key (status={:#x})", status);
        }
    }
}

fn allocate_redirect_context(bytes: &[u8]) -> *mut c_void {
    if bytes.is_empty() {
        return ptr::null_mut();
    }

    let ptr = unsafe {
        // SAFETY: allocation size matches the subsequent copy length.
        //
        // Ownership contract:
        // - this driver owns the returned buffer until it is attached to a
        //   writable `FWPS_CONNECT_REQUEST0` and handed back with
        //   `FwpsApplyModifiedLayerData0`;
        // - once applied, WFP owns `localRedirectContext` and frees it when the
        //   proxied flow is removed (Windows 8+ per `FWPS_CONNECT_REQUEST0`
        //   docs);
        // - if we fail before attaching it, the caller must free it.
        ExAllocatePoolWithTag(NON_PAGED_POOL, bytes.len(), SAFECHAIN_POOL_TAG)
    };
    if ptr.is_null() {
        log::driver_log_warn!(
            "failed to allocate redirect context buffer (len={})",
            bytes.len()
        );
        return ptr::null_mut();
    }

    unsafe {
        // SAFETY: `ptr` is valid for `bytes.len()` bytes and the slices do not overlap.
        ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
    }

    ptr
}

#[cfg(test)]
#[path = "../wfp_tests.rs"]
mod tests;
