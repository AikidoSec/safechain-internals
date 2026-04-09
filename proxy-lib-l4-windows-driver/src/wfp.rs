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
//! - `FwpsRedirectHandleCreate0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsredirecthandlecreate0
//! - `FwpsQueryConnectionRedirectState0`:
//!   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
//!
//! Header references used for the owned FFI/constants below:
//! - `fwpsk.h` (`km`): callout registration, classify output, metadata flags,
//!   redirect state, connect request structures
//! - `fwpstypes.h` / `fwptypes.h` (`shared`): metadata helper structs and
//!   generic WFP value types
//! - `ws2def.h` / `ws2ipdef.h` (`shared`): socket address families and layouts
//! - `wdm.h` / `ntstatus.h`: pool allocation and common `NTSTATUS` values

use alloc::{string::String, vec::Vec};
use core::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
};

use safechain_proxy_lib_nostd::{
    net::is_passthrough_ip,
    windows::{
        driver_protocol::{
            WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
            WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6, WFP_PROVIDER_SAFECHAIN_L4_PROXY,
            WindowsGuid,
        },
        redirect_ctx::ProxyRedirectContext,
    },
};
use spin::Mutex;
use wdk_sys::{GUID, NTSTATUS, STATUS_SUCCESS};

use crate::{driver_controller, log};

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

#[inline(always)]
pub fn is_local_destination(destination: SocketAddr) -> bool {
    is_passthrough_ip(destination.ip())
}

#[derive(Clone, Copy)]
struct KernelCalloutRegistration {
    callout_id_v4: u32,
    callout_id_v6: Option<u32>,
    redirect_handle: usize,
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

    let mut redirect_handle = ptr::null_mut();
    let redirect_status = unsafe {
        // SAFETY: output pointer is valid for the duration of the call.
        FwpsRedirectHandleCreate0(&GUID_PROVIDER_SAFECHAIN_L4_PROXY, 0, &mut redirect_handle)
    };
    if redirect_status != STATUS_SUCCESS {
        return redirect_status;
    }

    let mut callout_id_v4 = 0_u32;
    let mut callout_id_v6 = None;

    let callout_v4 = FWPS_CALLOUT1 {
        calloutKey: GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
        flags: 0,
        classifyFn: Some(on_callout_classify),
        notifyFn: Some(on_callout_notify),
        flowDeleteFn: Some(on_callout_flow_delete),
    };
    let status_v4 = unsafe {
        // SAFETY: arguments are valid pointers for the duration of the call.
        FwpsCalloutRegister1(device_object, &callout_v4, &mut callout_id_v4)
    };
    if status_v4 != STATUS_SUCCESS {
        unsafe {
            // SAFETY: handle was created successfully above.
            FwpsRedirectHandleDestroy0(redirect_handle);
        }
        return status_v4;
    }

    if enable_ipv6 {
        let mut v6_id = 0_u32;
        let callout_v6 = FWPS_CALLOUT1 {
            calloutKey: GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
            flags: 0,
            classifyFn: Some(on_callout_classify),
            notifyFn: Some(on_callout_notify),
            flowDeleteFn: Some(on_callout_flow_delete),
        };
        let status_v6 = unsafe {
            // SAFETY: arguments are valid pointers for the duration of the call.
            FwpsCalloutRegister1(device_object, &callout_v6, &mut v6_id)
        };
        if status_v6 != STATUS_SUCCESS {
            unsafe {
                // SAFETY: v4 callout and redirect handle were created successfully above.
                let _ =
                    FwpsCalloutUnregisterByKey0(&GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4);
                FwpsRedirectHandleDestroy0(redirect_handle);
            }
            return status_v6;
        }
        callout_id_v6 = Some(v6_id);
    }

    *registration = Some(KernelCalloutRegistration {
        callout_id_v4,
        callout_id_v6,
        redirect_handle: redirect_handle as usize,
    });

    // TODO: owned user-mode management plane (Fwpm*) to:
    // - create/update provider and sublayer
    // - add FWPM_CALLOUT entries for these callout keys
    // - add ALE_CONNECT_REDIRECT v4/v6 filters that target these callouts
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
        FwpsRedirectHandleDestroy0(reg.redirect_handle as *mut c_void);
    }

    log::driver_log_info!(
        "kernel callouts unregistered (v4_id={}, v6_id={:?})",
        reg.callout_id_v4,
        reg.callout_id_v6
    );
}

/// WFP notify callback for callout lifecycle/filter notifications.
unsafe extern "system" fn on_callout_notify(
    _notify_type: u32,
    _filter_key: *const GUID,
    _filter: *mut FWPS_FILTER1,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// WFP flow-delete callback.
unsafe extern "system" fn on_callout_flow_delete(
    _layer_id: u16,
    _callout_id: u32,
    _flow_context: u64,
) {
}

/// WFP classify callback where redirect decisions are applied.
unsafe extern "system" fn on_callout_classify(
    _in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const c_void,
    _layer_data: *mut c_void,
    classify_context: *const c_void,
    filter: *const FWPS_FILTER1,
    _flow_context: u64,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    if classify_context.is_null() || filter.is_null() || classify_out.is_null() {
        return;
    }

    let registration = KERNEL_CALLOUT_REGISTRATION.lock().as_ref().copied();
    let Some(registration) = registration else {
        return;
    };

    if should_skip_self_redirect(in_meta_values, registration) {
        if unsafe { ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 } {
            unsafe {
                // SAFETY: classify_out is a valid WFP output buffer for this callback.
                (*classify_out).actionType = FWP_ACTION_CONTINUE;
            }
        }
        return;
    }

    let mut classify_handle = 0_u64;
    let status = unsafe {
        // SAFETY: classify_context is provided by WFP for the duration of this callback.
        FwpsAcquireClassifyHandle0(classify_context, 0, &mut classify_handle)
    };
    if status != STATUS_SUCCESS {
        log::driver_log_warn!("failed to acquire classify handle (status={:#x})", status);
        return;
    }

    let mut writable_layer_data = ptr::null_mut();
    let acquire_status = unsafe {
        // SAFETY: classify handle is valid and filter points to the active WFP filter.
        FwpsAcquireWritableLayerDataPointer0(
            classify_handle,
            (*filter).filterId,
            0,
            &mut writable_layer_data,
            classify_out,
        )
    };
    if acquire_status != STATUS_SUCCESS || writable_layer_data.is_null() {
        unsafe {
            // SAFETY: classify handle was acquired successfully above.
            FwpsReleaseClassifyHandle0(classify_handle);
        }
        if acquire_status != STATUS_SUCCESS {
            log::driver_log_warn!(
                "failed to acquire writable layer data (status={:#x})",
                acquire_status
            );
        }
        return;
    }

    let connect_request = writable_layer_data.cast::<FWPS_CONNECT_REQUEST0>();
    let remote =
        unsafe { sockaddr_storage_to_socket_addr(&(*connect_request).remoteAddressAndPort) };
    let Some(remote) = remote else {
        complete_writable_classify(classify_handle, writable_layer_data, classify_out);
        return;
    };

    let decision = driver_controller().classify_outbound_tcp_connect(WfpFlowMeta {
        remote,
        source_pid: None,
        source_process_path: None,
    });

    if let TcpRedirectDecision::Redirect {
        proxy_target,
        redirect_context,
    } = decision
    {
        let context_ptr = allocate_redirect_context(&redirect_context);
        if !redirect_context.is_empty() && context_ptr.is_null() {
            complete_writable_classify(classify_handle, writable_layer_data, classify_out);
            return;
        }

        let proxy_pid = driver_controller().proxy_process_id().unwrap_or(0);

        unsafe {
            // SAFETY: connect_request is the writable request returned by WFP for this classify.
            write_socket_addr_to_storage(
                &mut (*connect_request).remoteAddressAndPort,
                proxy_target,
            );
            (*connect_request).localRedirectTargetPID = proxy_pid;
            (*connect_request).localRedirectHandle = registration.redirect_handle as *mut c_void;
            (*connect_request).localRedirectContext = context_ptr;
            (*connect_request).localRedirectContextSize = redirect_context.len();

            if ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 {
                (*classify_out).actionType = FWP_ACTION_PERMIT;
                (*classify_out).rights &= !FWPS_RIGHT_ACTION_WRITE;
            }
        }
    }

    complete_writable_classify(classify_handle, writable_layer_data, classify_out);
}

fn should_skip_self_redirect(
    in_meta_values: *const c_void,
    registration: KernelCalloutRegistration,
) -> bool {
    if in_meta_values.is_null() {
        return false;
    }

    let metadata = in_meta_values.cast::<FWPS_INCOMING_METADATA_VALUES0>();
    let redirect_records_present = unsafe {
        // SAFETY: `metadata` points to the WFP metadata values for this classify invocation.
        ((*metadata).currentMetadataValues & FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) != 0
            && !(*metadata).redirectRecords.is_null()
    };

    if !redirect_records_present {
        return false;
    }

    let mut redirect_context = ptr::null_mut();
    let redirect_state = unsafe {
        // SAFETY:
        // 1. `redirectRecords` originates from WFP metadata for this classify invocation.
        // 2. `registration.redirect_handle` was created via `FwpsRedirectHandleCreate0`.
        // 3. `redirect_context` is a valid optional out pointer.
        FwpsQueryConnectionRedirectState0(
            (*metadata).redirectRecords,
            registration.redirect_handle as *mut c_void,
            &mut redirect_context,
        )
    };

    matches!(
        redirect_state,
        FWPS_CONNECTION_REDIRECTED_BY_SELF | FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF
    )
}

fn complete_writable_classify(
    classify_handle: u64,
    writable_layer_data: *mut c_void,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    unsafe {
        // SAFETY: both pointers were returned by the WFP APIs for this classify path.
        FwpsApplyModifiedLayerData0(classify_handle, writable_layer_data, 0);
        FwpsReleaseClassifyHandle0(classify_handle);
        if !classify_out.is_null() && ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 {
            (*classify_out).actionType = FWP_ACTION_CONTINUE;
        }
    }
}

fn allocate_redirect_context(bytes: &[u8]) -> *mut c_void {
    if bytes.is_empty() {
        return ptr::null_mut();
    }

    let ptr = unsafe {
        // SAFETY: allocation size matches the subsequent copy length.
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

unsafe fn sockaddr_storage_to_socket_addr(storage: &SockAddrStorage) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes([storage.bytes[0], storage.bytes[1]]);
    match family {
        AF_INET => {
            let port = u16::from_be_bytes([storage.bytes[2], storage.bytes[3]]);
            let addr = Ipv4Addr::from([
                storage.bytes[4],
                storage.bytes[5],
                storage.bytes[6],
                storage.bytes[7],
            ]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        AF_INET6 => {
            let port = u16::from_be_bytes([storage.bytes[2], storage.bytes[3]]);
            let scope_id = u32::from_ne_bytes([
                storage.bytes[24],
                storage.bytes[25],
                storage.bytes[26],
                storage.bytes[27],
            ]);
            let addr = Ipv6Addr::from([
                storage.bytes[8],
                storage.bytes[9],
                storage.bytes[10],
                storage.bytes[11],
                storage.bytes[12],
                storage.bytes[13],
                storage.bytes[14],
                storage.bytes[15],
                storage.bytes[16],
                storage.bytes[17],
                storage.bytes[18],
                storage.bytes[19],
                storage.bytes[20],
                storage.bytes[21],
                storage.bytes[22],
                storage.bytes[23],
            ]);
            Some(SocketAddr::new(IpAddr::V6(addr), port).set_ip_scope_id(scope_id))
        }
        _ => None,
    }
}

fn write_socket_addr_to_storage(storage: &mut SockAddrStorage, socket_addr: SocketAddr) {
    storage.bytes.fill(0);
    match socket_addr {
        SocketAddr::V4(addr) => {
            storage.bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            storage.bytes[2..4].copy_from_slice(&addr.port().to_be_bytes());
            storage.bytes[4..8].copy_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            storage.bytes[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            storage.bytes[2..4].copy_from_slice(&addr.port().to_be_bytes());
            storage.bytes[8..24].copy_from_slice(&addr.ip().octets());
            storage.bytes[24..28].copy_from_slice(&addr.scope_id().to_ne_bytes());
        }
    }
}

trait SocketAddrExt {
    fn set_ip_scope_id(self, scope_id: u32) -> SocketAddr;
}

impl SocketAddrExt for SocketAddr {
    fn set_ip_scope_id(self, scope_id: u32) -> SocketAddr {
        match self {
            SocketAddr::V4(addr) => SocketAddr::V4(addr),
            SocketAddr::V6(addr) => SocketAddr::V6(addr.set_scope_id(scope_id)),
        }
    }
}

trait SocketAddrV6Ext {
    fn set_scope_id(self, scope_id: u32) -> core::net::SocketAddrV6;
}

impl SocketAddrV6Ext for core::net::SocketAddrV6 {
    fn set_scope_id(self, scope_id: u32) -> core::net::SocketAddrV6 {
        core::net::SocketAddrV6::new(*self.ip(), self.port(), self.flowinfo(), scope_id)
    }
}

/// `STATUS_INVALID_PARAMETER` from `ntstatus.h`.
///
/// Used when callout registration is invoked with an invalid device object.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
const STATUS_INVALID_PARAMETER: NTSTATUS = -1_073_741_811_i32;
/// `FWPS_RIGHT_ACTION_WRITE` from `fwpsk.h`.
///
/// Indicates the callout may still write `FWPS_CLASSIFY_OUT0.actionType`.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_classify_out0
const FWPS_RIGHT_ACTION_WRITE: u32 = 0x0000_0001;
/// `FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE` from `fwpsk.h`.
///
/// Signals that `FWPS_INCOMING_METADATA_VALUES0.redirectRecords` is present.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0
const FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE: u32 = 0x4000_0000;
/// `FWP_ACTION_PERMIT` from `fwptypes.h`.
///
/// Used after rewriting the connect request so WFP allows the redirected flow.
/// Docs: https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_action_type
const FWP_ACTION_PERMIT: u32 = 0x0000_0002;
/// `FWP_ACTION_CONTINUE` from `fwptypes.h`.
///
/// Used when this callout leaves the decision unchanged.
/// Docs: https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_action_type
const FWP_ACTION_CONTINUE: u32 = 0x0000_0006;
/// `NonPagedPool` / `POOL_TYPE = 0` from `wdm.h`.
///
/// Redirect context buffers must be non-paged kernel memory.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type
const NON_PAGED_POOL: u32 = 0;
/// Driver-owned pool tag for redirect context allocations made via
/// `ExAllocatePoolWithTag`.
///
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag
const SAFECHAIN_POOL_TAG: u32 = u32::from_ne_bytes(*b"4LCS");
/// IPv4 address-family value from Winsock headers.
///
/// Docs: https://learn.microsoft.com/en-us/windows/win32/winsock/address-families
const AF_INET: u16 = 2;
/// IPv6 address-family value from Winsock headers.
///
/// Docs: https://learn.microsoft.com/en-us/windows/win32/winsock/address-families
const AF_INET6: u16 = 23;
/// `FWPS_CONNECTION_REDIRECTED_BY_SELF` enum value from
/// `FWPS_CONNECTION_REDIRECT_STATE`.
///
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
const FWPS_CONNECTION_REDIRECTED_BY_SELF: u32 = 1;
/// `FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF` enum value from
/// `FWPS_CONNECTION_REDIRECT_STATE`.
///
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
const FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF: u32 = 3;

/// Provider GUID for the SafeChain L4 redirector.
///
/// These GUIDs were generated once as stable random UUID-style identifiers and
/// then committed so kernel mode and user mode can refer to the same provider
/// and callouts consistently. This provider GUID is used for the redirect
/// handle created by `FwpsRedirectHandleCreate0`; the callout GUIDs below are
/// the identifiers that the user-mode `Fwpm*` management plane will register in
/// the WFP engine for IPv4 and IPv6 connect-redirection.
const GUID_PROVIDER_SAFECHAIN_L4_PROXY: GUID = guid(WFP_PROVIDER_SAFECHAIN_L4_PROXY);
/// Callout GUID for outbound IPv4 TCP connect redirection.
const GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4: GUID =
    guid(WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4);
/// Callout GUID for outbound IPv6 TCP connect redirection.
const GUID_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6: GUID =
    guid(WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6);

/// Helper for building `GUID` literals without expanding the entire WDK type
/// surface into this module.
const fn guid(parts: WindowsGuid) -> GUID {
    GUID {
        Data1: parts.data1,
        Data2: parts.data2,
        Data3: parts.data3,
        Data4: parts.data4,
    }
}

/// Function-pointer type matching `FWPS_CALLOUT_CLASSIFY_FN1`.
///
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn1
type FwpsCalloutClassifyFn1 = Option<
    unsafe extern "system" fn(
        in_fixed_values: *const FWPS_INCOMING_VALUES0,
        in_meta_values: *const c_void,
        layer_data: *mut c_void,
        classify_context: *const c_void,
        filter: *const FWPS_FILTER1,
        flow_context: u64,
        classify_out: *mut FWPS_CLASSIFY_OUT0,
    ),
>;

/// Function-pointer type matching `FWPS_CALLOUT_NOTIFY_FN1`.
///
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_notify_fn1
type FwpsCalloutNotifyFn1 = Option<
    unsafe extern "system" fn(
        notify_type: u32,
        filter_key: *const GUID,
        filter: *mut FWPS_FILTER1,
    ) -> NTSTATUS,
>;

/// Function-pointer type matching `FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0`.
///
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0
type FwpsCalloutFlowDeleteNotifyFn0 =
    Option<unsafe extern "system" fn(layer_id: u16, callout_id: u32, flow_context: u64)>;

#[repr(C)]
#[allow(non_snake_case)]
/// Minimal owned mirror of `FWPS_CALLOUT1`.
///
/// This binds a GUID to the classify/notify/delete callbacks registered with
/// the WFP runtime.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout1
struct FWPS_CALLOUT1 {
    calloutKey: GUID,
    flags: u32,
    classifyFn: FwpsCalloutClassifyFn1,
    notifyFn: FwpsCalloutNotifyFn1,
    flowDeleteFn: FwpsCalloutFlowDeleteNotifyFn0,
}

#[repr(C)]
#[allow(non_snake_case)]
/// Minimal header subset of `FWPS_INCOMING_VALUES0`.
///
/// The current implementation does not inspect the per-field `incomingValue`
/// array, so only the leading fields are mirrored.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_values0
struct FWPS_INCOMING_VALUES0 {
    layerId: u16,
    valueCount: u32,
    incomingValue: *const c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
/// Minimal filter view containing the filter id used with
/// `FwpsAcquireWritableLayerDataPointer0`.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_filter1
struct FWPS_FILTER1 {
    filterId: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
/// Owned mirror of `FWPS_CLASSIFY_OUT0`.
///
/// This is where the callout reads rights and reports the action it selected.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_classify_out0
struct FWPS_CLASSIFY_OUT0 {
    actionType: u32,
    outContext: u64,
    filterId: u64,
    rights: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
/// `FWPS_DISCARD_METADATA0` from `fwpstypes.h`.
///
/// Present here because it is embedded in incoming metadata before the fields
/// this callout currently reads.
struct FWPS_DISCARD_METADATA0 {
    discardModule: u32,
    discardReason: u32,
    filterId: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
/// `FWP_BYTE_BLOB` from `fwptypes.h`, used for optional process-path metadata.
///
/// Docs: https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_byte_blob
struct FWP_BYTE_BLOB {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
#[allow(non_snake_case)]
/// `FWPS_INBOUND_FRAGMENT_METADATA0` from `fwpstypes.h`, included for layout
/// compatibility with `FWPS_INCOMING_METADATA_VALUES0`.
struct FWPS_INBOUND_FRAGMENT_METADATA0 {
    fragmentIdentification: u32,
    fragmentOffset: u16,
    fragmentLength: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
/// Layout-compatible subset of `IP_ADDRESS_PREFIX`.
///
/// Header reference: `netioapi.h`
struct IP_ADDRESS_PREFIX {
    prefix: [u8; 28],
    prefixLength: u8,
    padding: [u8; 3],
}

#[repr(C)]
#[allow(non_snake_case)]
/// Owned mirror of `FWPS_INCOMING_METADATA_VALUES0` up to `redirectRecords`.
///
/// The callout uses this to inspect redirect records and prevent loops. It also
/// preserves nearby fields so the layout matches the WDK definition up to that
/// point.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0
struct FWPS_INCOMING_METADATA_VALUES0 {
    currentMetadataValues: u32,
    flags: u32,
    reserved: u64,
    discardMetadata: FWPS_DISCARD_METADATA0,
    flowHandle: u64,
    ipHeaderSize: u32,
    transportHeaderSize: u32,
    processPath: *mut FWP_BYTE_BLOB,
    token: u64,
    processId: u64,
    sourceInterfaceIndex: u32,
    destinationInterfaceIndex: u32,
    compartmentId: u32,
    fragmentMetadata: FWPS_INBOUND_FRAGMENT_METADATA0,
    pathMtu: u32,
    completionHandle: *mut c_void,
    transportEndpointHandle: u64,
    remoteScopeId: u32,
    controlData: *mut c_void,
    controlDataLength: u32,
    packetDirection: i32,
    headerIncludeHeader: *mut c_void,
    headerIncludeHeaderLength: u32,
    destinationPrefix: IP_ADDRESS_PREFIX,
    frameLength: u16,
    _padding0: u16,
    parentEndpointHandle: u64,
    icmpIdAndSequence: u32,
    localRedirectTargetPID: u32,
    originalDestination: *mut c_void,
    redirectRecords: *mut c_void,
}

#[repr(C)]
/// Raw `SOCKADDR_STORAGE`-sized buffer used for connect-request address fields.
///
/// Header reference: `ws2def.h`
struct SockAddrStorage {
    bytes: [u8; 128],
}

#[repr(C)]
#[allow(non_snake_case)]
/// Owned mirror of `FWPS_CONNECT_REQUEST0`, the writable ALE connect request.
///
/// The driver rewrites the remote address, sets redirect context, and stamps
/// the local redirect handle/PID on this structure.
/// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0
struct FWPS_CONNECT_REQUEST0 {
    localAddressAndPort: SockAddrStorage,
    remoteAddressAndPort: SockAddrStorage,
    portReservationToken: u64,
    localRedirectTargetPID: u32,
    previousVersion: *mut FWPS_CONNECT_REQUEST0,
    modifierFilterId: u64,
    localRedirectHandle: *mut c_void,
    localRedirectContext: *mut c_void,
    localRedirectContextSize: usize,
}

#[link(name = "fwpkclnt")]
unsafe extern "system" {
    /// Registers a kernel callout under the provided GUID and callback set.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister1
    fn FwpsCalloutRegister1(
        device_object: *mut c_void,
        callout: *const FWPS_CALLOUT1,
        callout_id: *mut u32,
    ) -> NTSTATUS;

    /// Unregisters a callout by GUID.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutunregisterbykey0
    fn FwpsCalloutUnregisterByKey0(callout_key: *const GUID) -> NTSTATUS;

    /// Creates a redirect handle used to tag redirected flows for this
    /// provider.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsredirecthandlecreate0
    fn FwpsRedirectHandleCreate0(
        provider_guid: *const GUID,
        flags: u32,
        redirect_handle: *mut *mut c_void,
    ) -> NTSTATUS;

    /// Destroys a redirect handle created by `FwpsRedirectHandleCreate0`.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsredirecthandledestroy0
    fn FwpsRedirectHandleDestroy0(redirect_handle: *mut c_void);

    /// Acquires a classify handle so the callout can later request writable
    /// layer data.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquireclassifyhandle0
    fn FwpsAcquireClassifyHandle0(
        classify_context: *const c_void,
        flags: u32,
        classify_handle: *mut u64,
    ) -> NTSTATUS;

    /// Releases a classify handle acquired earlier in the callback.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsreleaseclassifyhandle0
    fn FwpsReleaseClassifyHandle0(classify_handle: u64);

    /// Returns writable layer data for the current classify operation.
    ///
    /// At ALE connect-redirect layers this points to a `FWPS_CONNECT_REQUEST0`.
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
    fn FwpsAcquireWritableLayerDataPointer0(
        classify_handle: u64,
        filter_id: u64,
        flags: u32,
        writable_layer_data: *mut *mut c_void,
        classify_out: *mut FWPS_CLASSIFY_OUT0,
    ) -> NTSTATUS;

    /// Applies any modifications made to writable layer data.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
    fn FwpsApplyModifiedLayerData0(
        classify_handle: u64,
        modified_layer_data: *mut c_void,
        flags: u32,
    );

    /// Queries the redirect state for the connection represented by redirect
    /// records.
    ///
    /// Used here to detect connections already redirected by this driver and
    /// avoid redirect loops.
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
    fn FwpsQueryConnectionRedirectState0(
        redirect_records: *mut c_void,
        redirect_handle: *mut c_void,
        redirect_context: *mut *mut c_void,
    ) -> u32;
}

#[link(name = "NtosKrnl")]
unsafe extern "system" {
    /// Allocates kernel pool memory tagged for later debugging/diagnostics.
    ///
    /// Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag
    fn ExAllocatePoolWithTag(pool_type: u32, number_of_bytes: usize, tag: u32) -> *mut c_void;
}

#[cfg(test)]
#[path = "wfp_tests.rs"]
mod tests;
