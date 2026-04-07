//! Windows Filtering Platform (WFP) kernel callout integration.
//!
//! This module intentionally keeps a very small owned FFI surface so we are not
//! blocked by third-party wrappers and can audit every unsafe boundary.
//!
//! Official references (WDK / Microsoft Learn):
//! - `fwpsk.h` API index:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/
//! - `FWPS_CALLOUT0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout0_
//! - `FwpsCalloutRegister0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
//! - `FwpsCalloutUnregisterByKey0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutunregisterbykey0
//!
//! Related management-plane APIs (configured out-of-band by a service/tool):
//! - `fwpmu.h` / `fwpmk.h` (`FwpmEngineOpen*`, `FwpmCalloutAdd*`, `FwpmFilterAdd*`)

use alloc::{string::String, vec::Vec};
use core::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use safechain_proxy_lib_windows_core::redirect_ctx::ProxyRedirectContext;
use spin::Mutex;
use wdk_sys::{GUID, NTSTATUS, STATUS_SUCCESS};

use crate::log;

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
        redirect_context: Vec<u8>,
    },
}

pub fn build_redirect_context(flow: &WfpFlowMeta) -> Result<Vec<u8>, postcard::Error> {
    let ctx = ProxyRedirectContext::new(flow.remote)
        .with_source_pid(flow.source_pid)
        .with_source_process_path(flow.source_process_path.clone());
    postcard::to_allocvec(&ctx)
}

pub fn is_local_destination(destination: SocketAddr) -> bool {
    match destination.ip() {
        IpAddr::V4(addr) => is_local_ipv4(addr),
        IpAddr::V6(addr) => is_local_ipv6(addr),
    }
}

fn is_local_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_broadcast()
}

fn is_local_ipv6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_unique_local()
        || addr.is_unicast_link_local()
}

#[derive(Clone, Copy)]
struct KernelCalloutRegistration {
    callout_id_v4: u32,
    callout_id_v6: Option<u32>,
}

static KERNEL_CALLOUT_REGISTRATION: Mutex<Option<KernelCalloutRegistration>> = Mutex::new(None);

pub fn register_callouts(device_object: *mut c_void, enable_ipv6: bool) -> NTSTATUS {
    if device_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut registration = KERNEL_CALLOUT_REGISTRATION.lock();
    if registration.is_some() {
        return STATUS_SUCCESS;
    }

    let mut callout_id_v4 = 0_u32;
    let mut callout_id_v6 = None;

    let callout_v4 = FWPS_CALLOUT0 {
        calloutKey: GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
        flags: 0,
        classifyFn: Some(on_callout_classify),
        notifyFn: Some(on_callout_notify),
        flowDeleteFn: Some(on_callout_flow_delete),
    };
    let status_v4 = unsafe {
        // SAFETY: arguments are valid pointers for the duration of the call.
        FwpsCalloutRegister0(device_object, &callout_v4, &mut callout_id_v4)
    };
    if status_v4 != STATUS_SUCCESS {
        return status_v4;
    }

    if enable_ipv6 {
        let mut v6_id = 0_u32;
        let callout_v6 = FWPS_CALLOUT0 {
            calloutKey: GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
            flags: 0,
            classifyFn: Some(on_callout_classify),
            notifyFn: Some(on_callout_notify),
            flowDeleteFn: Some(on_callout_flow_delete),
        };
        let status_v6 = unsafe {
            // SAFETY: arguments are valid pointers for the duration of the call.
            FwpsCalloutRegister0(device_object, &callout_v6, &mut v6_id)
        };
        if status_v6 != STATUS_SUCCESS {
            unsafe {
                // SAFETY: callout v4 was successfully registered with this key.
                let _ =
                    FwpsCalloutUnregisterByKey0(&GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4);
            }
            return status_v6;
        }
        callout_id_v6 = Some(v6_id);
    }

    *registration = Some(KernelCalloutRegistration {
        callout_id_v4,
        callout_id_v6,
    });

    // TODO: owned user-mode management plane (Fwpm*) to:
    // - create/update provider and sublayer
    // - add FWPM_CALLOUT entries for these callout keys
    // - add ALE_AUTH_CONNECT v4/v6 filters that target these callouts
    log::driver_log_info!(
        "kernel callouts registered (v4_id={}, v6_id={:?})",
        callout_id_v4,
        callout_id_v6
    );
    STATUS_SUCCESS
}

pub fn unregister_callouts() {
    let Some(reg) = KERNEL_CALLOUT_REGISTRATION.lock().take() else {
        return;
    };

    unsafe {
        // SAFETY: keys correspond to registered callouts from register_callouts.
        if reg.callout_id_v6.is_some() {
            let _ = FwpsCalloutUnregisterByKey0(&GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6);
        }
        let _ = FwpsCalloutUnregisterByKey0(&GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4);
    }

    log::driver_log_info!(
        "kernel callouts unregistered (v4_id={}, v6_id={:?})",
        reg.callout_id_v4,
        reg.callout_id_v6
    );
}

/// WFP notify callback for callout lifecycle/filter notifications.
///
/// # Safety
/// Called by the WFP engine with pointers valid for the duration of the call,
/// per the `FWPS_CALLOUT_NOTIFY_FN0` contract.
unsafe extern "system" fn on_callout_notify(
    _notify_type: u32,
    _filter_key: *const GUID,
    _filter: *mut c_void,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// WFP flow-delete callback.
///
/// # Safety
/// Invoked by WFP according to `FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0`. The
/// `flow_context` value, if used, must be interpreted consistently with the
/// context installed by this callout.
unsafe extern "system" fn on_callout_flow_delete(
    _layer_id: u16,
    _callout_id: u32,
    _flow_context: u64,
) {
}

/// WFP classify callback where redirect decisions are applied.
///
/// # Safety
/// Called by WFP with layer/metadata/classify pointers described by
/// `FWPS_CALLOUT_CLASSIFY_FN0`. Pointer interpretation must match the active
/// layer and metadata bitmask before dereferencing.
unsafe extern "system" fn on_callout_classify(
    _in_fixed_values: *const c_void,
    _in_meta_values: *const c_void,
    _layer_data: *mut c_void,
    _classify_context: *const c_void,
    _filter: *const c_void,
    _flow_context: u64,
    _classify_out: *mut c_void,
) {
    // TODO: decode FWPS metadata + remote endpoint and apply proxy redirect decision:
    // 1. read PID + remote endpoint
    // 2. map to ProxyDriverController::classify_outbound_tcp_connect
    // 3. inject redirect target + redirect context
}

const STATUS_INVALID_PARAMETER: NTSTATUS = -1_073_741_811_i32;

const GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4: GUID = guid(
    0x5c6262c4,
    0x8ef6,
    0x43d8,
    [0xa8, 0xf9, 0x48, 0x63, 0x6b, 0x17, 0x2b, 0xb8],
);
const GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6: GUID = guid(
    0x4f05f1f8,
    0x9093,
    0x44f1,
    [0xa8, 0xe7, 0x2d, 0x84, 0x1a, 0x3e, 0x2e, 0x5a],
);

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> GUID {
    GUID {
        Data1: data1,
        Data2: data2,
        Data3: data3,
        Data4: data4,
    }
}

/// Classify callback invoked by WFP for matching layers/filters.
///
/// Signature based on `FWPS_CALLOUT_CLASSIFY_FN0` (`fwpsk.h`).
type FwpsCalloutClassifyFn0 = Option<
    unsafe extern "system" fn(
        in_fixed_values: *const c_void,
        in_meta_values: *const c_void,
        layer_data: *mut c_void,
        classify_context: *const c_void,
        filter: *const c_void,
        flow_context: u64,
        classify_out: *mut c_void,
    ),
>;

/// Notification callback (`FWPS_CALLOUT_NOTIFY_FN0`, `fwpsk.h`).
type FwpsCalloutNotifyFn0 = Option<
    unsafe extern "system" fn(
        notify_type: u32,
        filter_key: *const GUID,
        filter: *mut c_void,
    ) -> NTSTATUS,
>;

/// Flow-delete callback (`FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0`, `fwpsk.h`).
type FwpsCalloutFlowDeleteNotifyFn0 =
    Option<unsafe extern "system" fn(layer_id: u16, callout_id: u32, flow_context: u64)>;

#[repr(C)]
#[allow(non_snake_case)]
struct FWPS_CALLOUT0 {
    /// Callout GUID key (`FWPS_CALLOUT0::calloutKey`).
    calloutKey: GUID,
    /// Registration flags (`FWPS_CALLOUT0::flags`).
    flags: u32,
    /// Classify callback pointer.
    classifyFn: FwpsCalloutClassifyFn0,
    /// Notify callback pointer.
    notifyFn: FwpsCalloutNotifyFn0,
    /// Flow-delete callback pointer.
    flowDeleteFn: FwpsCalloutFlowDeleteNotifyFn0,
}

#[link(name = "fwpkclnt")]
unsafe extern "system" {
    /// Kernel-mode callout registration API from `fwpkclnt.lib` / `fwpsk.h`.
    ///
    /// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
    fn FwpsCalloutRegister0(
        device_object: *mut c_void,
        callout: *const FWPS_CALLOUT0,
        callout_id: *mut u32,
    ) -> NTSTATUS;

    /// Kernel-mode callout unregistration-by-key API from `fwpkclnt.lib` / `fwpsk.h`.
    ///
    /// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutunregisterbykey0
    fn FwpsCalloutUnregisterByKey0(callout_key: *const GUID) -> NTSTATUS;
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use super::{build_redirect_context, is_local_destination, WfpFlowMeta};
    use alloc::string::String;
    use safechain_proxy_lib_windows_core::redirect_ctx::ProxyRedirectContext;

    #[test]
    fn local_destination_detection_covers_common_ranges() {
        assert!(is_local_destination(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            80
        )));
        assert!(is_local_destination(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            80
        )));
        assert!(is_local_destination(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            443
        )));
    }

    #[test]
    fn redirect_context_contains_destination_and_pid() {
        let flow = WfpFlowMeta {
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            source_pid: Some(123),
            source_process_path: Some(String::from("C:\\Windows\\System32\\curl.exe")),
        };
        let encoded = build_redirect_context(&flow).expect("encoding failed");
        let decoded: ProxyRedirectContext =
            postcard::from_bytes(&encoded).expect("context decode failed");
        assert_eq!(decoded.destination(), flow.remote);
        assert_eq!(decoded.source_pid(), Some(123));
        assert_eq!(
            decoded.source_process_path(),
            Some("C:\\Windows\\System32\\curl.exe")
        );
    }
}
