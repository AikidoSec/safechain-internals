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

use alloc::{string::String, vec::Vec};
use core::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
};

use safechain_proxy_lib_windows_core::redirect_ctx::ProxyRedirectContext;
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
    _in_meta_values: *const c_void,
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

const STATUS_INVALID_PARAMETER: NTSTATUS = -1_073_741_811_i32;
const FWPS_RIGHT_ACTION_WRITE: u32 = 0x0000_0001;
const FWP_ACTION_PERMIT: u32 = 0x0000_0002;
const FWP_ACTION_CONTINUE: u32 = 0x0000_0006;
const NON_PAGED_POOL: u32 = 0;
const SAFECHAIN_POOL_TAG: u32 = u32::from_ne_bytes(*b"4LCS");
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

const GUID_PROVIDER_SAFECHAIN_L4_PROXY: GUID = guid(
    0x6a625bb6,
    0xf310,
    0x443e,
    [0x98, 0x50, 0x28, 0x0f, 0xac, 0xdc, 0x1a, 0x21],
);
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

type FwpsCalloutNotifyFn1 = Option<
    unsafe extern "system" fn(
        notify_type: u32,
        filter_key: *const GUID,
        filter: *mut FWPS_FILTER1,
    ) -> NTSTATUS,
>;

type FwpsCalloutFlowDeleteNotifyFn0 =
    Option<unsafe extern "system" fn(layer_id: u16, callout_id: u32, flow_context: u64)>;

#[repr(C)]
#[allow(non_snake_case)]
struct FWPS_CALLOUT1 {
    calloutKey: GUID,
    flags: u32,
    classifyFn: FwpsCalloutClassifyFn1,
    notifyFn: FwpsCalloutNotifyFn1,
    flowDeleteFn: FwpsCalloutFlowDeleteNotifyFn0,
}

#[repr(C)]
#[allow(non_snake_case)]
struct FWPS_INCOMING_VALUES0 {
    layerId: u16,
    valueCount: u32,
    incomingValue: *const c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
struct FWPS_FILTER1 {
    filterId: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct FWPS_CLASSIFY_OUT0 {
    actionType: u32,
    outContext: u64,
    filterId: u64,
    rights: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct SockAddrStorage {
    bytes: [u8; 128],
}

#[repr(C)]
#[allow(non_snake_case)]
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
    fn FwpsCalloutRegister1(
        device_object: *mut c_void,
        callout: *const FWPS_CALLOUT1,
        callout_id: *mut u32,
    ) -> NTSTATUS;

    fn FwpsCalloutUnregisterByKey0(callout_key: *const GUID) -> NTSTATUS;

    fn FwpsRedirectHandleCreate0(
        provider_guid: *const GUID,
        flags: u32,
        redirect_handle: *mut *mut c_void,
    ) -> NTSTATUS;

    fn FwpsRedirectHandleDestroy0(redirect_handle: *mut c_void);

    fn FwpsAcquireClassifyHandle0(
        classify_context: *const c_void,
        flags: u32,
        classify_handle: *mut u64,
    ) -> NTSTATUS;

    fn FwpsReleaseClassifyHandle0(classify_handle: u64);

    fn FwpsAcquireWritableLayerDataPointer0(
        classify_handle: u64,
        filter_id: u64,
        flags: u32,
        writable_layer_data: *mut *mut c_void,
        classify_out: *mut FWPS_CLASSIFY_OUT0,
    ) -> NTSTATUS;

    fn FwpsApplyModifiedLayerData0(
        classify_handle: u64,
        modified_layer_data: *mut c_void,
        flags: u32,
    );
}

#[link(name = "NtosKrnl")]
unsafe extern "system" {
    fn ExAllocatePoolWithTag(pool_type: u32, number_of_bytes: usize, tag: u32) -> *mut c_void;
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use safechain_proxy_lib_windows_core::redirect_ctx::ProxyRedirectContext;

    use super::{WfpFlowMeta, build_redirect_context, is_local_destination};

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
