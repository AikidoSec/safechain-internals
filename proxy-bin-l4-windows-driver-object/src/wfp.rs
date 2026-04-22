use std::ptr;

use rama_core::{
    error::{BoxError, ErrorExt, extra::OpaqueError},
    telemetry::tracing::{debug, info, warn},
};
use safechain_proxy_lib_nostd::windows::driver_protocol::{
    WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4, WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
    WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4,
    WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6, WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
    WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V6, WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4,
    WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6, WFP_PROVIDER_SAFECHAIN_L4_PROXY,
    WFP_SUBLAYER_SAFECHAIN_L4_PROXY, WindowsGuid,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_SUCCESS, FWP_E_CALLOUT_NOT_FOUND, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
    },
    NetworkManagement::WindowsFilteringPlatform::*,
};

const RPC_C_AUTHN_DEFAULT: u32 = 0xffff_ffff;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

pub fn ensure_wfp_objects() -> Result<(), BoxError> {
    info!("ensuring dual-stack WFP provider/sublayer/callouts/filters are installed");
    let engine = EngineHandle::open()?;
    let transaction = Transaction::begin(&engine)?;

    remove_wfp_objects_inner(&engine)?;
    add_provider(&engine)?;
    add_sublayer(&engine)?;
    add_callout(
        &engine,
        WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        "SafeChain TCP Connect Redirect v4",
        "Kernel callout for SafeChain IPv4 TCP connect redirection.",
    )?;
    add_filter(
        &engine,
        WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4,
        "SafeChain TCP Redirect Filter v4",
        "Invokes the SafeChain IPv4 TCP connect-redirect callout.",
        IPPROTO_TCP,
        None,
        FWP_ACTION_CALLOUT_INSPECTION,
    )?;

    add_callout(
        &engine,
        WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        "SafeChain TCP Connect Redirect v6",
        "Kernel callout for SafeChain IPv6 TCP connect redirection.",
    )?;
    add_filter(
        &engine,
        WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6,
        "SafeChain TCP Redirect Filter v6",
        "Invokes the SafeChain IPv6 TCP connect-redirect callout.",
        IPPROTO_TCP,
        None,
        FWP_ACTION_CALLOUT_INSPECTION,
    )?;

    add_callout(
        &engine,
        WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        "SafeChain UDP Auth Connect Block v4",
        "Kernel callout for SafeChain IPv4 UDP/443 browser blocking.",
    )?;
    add_filter(
        &engine,
        WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4,
        "SafeChain UDP Block Filter v4",
        "Invokes the SafeChain IPv4 UDP auth-connect block callout.",
        IPPROTO_UDP,
        Some(443),
        FWP_ACTION_CALLOUT_TERMINATING,
    )?;

    add_callout(
        &engine,
        WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        "SafeChain UDP Auth Connect Block v6",
        "Kernel callout for SafeChain IPv6 UDP/443 browser blocking.",
    )?;
    add_filter(
        &engine,
        WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6,
        "SafeChain UDP Block Filter v6",
        "Invokes the SafeChain IPv6 UDP auth-connect block callout.",
        IPPROTO_UDP,
        Some(443),
        FWP_ACTION_CALLOUT_TERMINATING,
    )?;

    transaction.commit()
}

pub fn remove_wfp_objects() -> Result<(), BoxError> {
    info!("removing WFP provider/sublayer/callouts/filters");
    let engine = EngineHandle::open()?;
    let transaction = Transaction::begin(&engine)?;
    remove_wfp_objects_inner(&engine)?;
    transaction.commit()
}

fn remove_wfp_objects_inner(engine: &EngineHandle) -> Result<(), BoxError> {
    unsafe {
        // SAFETY: object keys are stable GUIDs owned by this application.
        check_delete_status(
            FwpmFilterDeleteByKey0(
                engine.0,
                &guid(WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6),
            ),
            "FwpmFilterDeleteByKey0(udp v6)",
            FWP_E_FILTER_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmFilterDeleteByKey0(
                engine.0,
                &guid(WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4),
            ),
            "FwpmFilterDeleteByKey0(udp v4)",
            FWP_E_FILTER_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmFilterDeleteByKey0(
                engine.0,
                &guid(WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V6),
            ),
            "FwpmFilterDeleteByKey0(v6)",
            FWP_E_FILTER_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmFilterDeleteByKey0(
                engine.0,
                &guid(WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V4),
            ),
            "FwpmFilterDeleteByKey0(v4)",
            FWP_E_FILTER_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmCalloutDeleteByKey0(
                engine.0,
                &guid(WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6),
            ),
            "FwpmCalloutDeleteByKey0(udp v6)",
            FWP_E_CALLOUT_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmCalloutDeleteByKey0(
                engine.0,
                &guid(WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4),
            ),
            "FwpmCalloutDeleteByKey0(udp v4)",
            FWP_E_CALLOUT_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmCalloutDeleteByKey0(
                engine.0,
                &guid(WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6),
            ),
            "FwpmCalloutDeleteByKey0(v6)",
            FWP_E_CALLOUT_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmCalloutDeleteByKey0(
                engine.0,
                &guid(WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4),
            ),
            "FwpmCalloutDeleteByKey0(v4)",
            FWP_E_CALLOUT_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmSubLayerDeleteByKey0(engine.0, &guid(WFP_SUBLAYER_SAFECHAIN_L4_PROXY)),
            "FwpmSubLayerDeleteByKey0",
            FWP_E_SUBLAYER_NOT_FOUND as u32,
        )?;
        check_delete_status(
            FwpmProviderDeleteByKey0(engine.0, &guid(WFP_PROVIDER_SAFECHAIN_L4_PROXY)),
            "FwpmProviderDeleteByKey0",
            FWP_E_PROVIDER_NOT_FOUND as u32,
        )?;
    }

    Ok(())
}

fn add_provider(engine: &EngineHandle) -> Result<(), BoxError> {
    debug!("adding WFP provider");
    let mut name = WideString::new("SafeChain L4 Proxy");
    let mut description = WideString::new("Provider for SafeChain Windows L4 redirect objects.");
    let provider_key = guid(WFP_PROVIDER_SAFECHAIN_L4_PROXY);
    let provider = FWPM_PROVIDER0 {
        providerKey: provider_key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: 0,
        providerData: zeroed_blob(),
        serviceName: ptr::null_mut(),
    };

    let status = unsafe {
        // SAFETY: pointers remain valid for the duration of the call.
        FwpmProviderAdd0(engine.0, &provider, ptr::null_mut())
    };
    check_status(status, "FwpmProviderAdd0")
}

fn add_sublayer(engine: &EngineHandle) -> Result<(), BoxError> {
    debug!("adding WFP sublayer");
    let mut name = WideString::new("SafeChain L4 Redirect");
    let mut description = WideString::new("Sublayer for SafeChain TCP connect redirection.");
    let mut provider_key = guid(WFP_PROVIDER_SAFECHAIN_L4_PROXY);
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: guid(WFP_SUBLAYER_SAFECHAIN_L4_PROXY),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: 0,
        providerKey: &mut provider_key,
        providerData: zeroed_blob(),
        weight: 0x8000,
    };

    let status = unsafe {
        // SAFETY: pointers remain valid for the duration of the call.
        FwpmSubLayerAdd0(engine.0, &sublayer, ptr::null_mut())
    };
    check_status(status, "FwpmSubLayerAdd0")
}

fn add_callout(
    engine: &EngineHandle,
    callout_key: WindowsGuid,
    layer_key: windows_sys::core::GUID,
    name: &str,
    description: &str,
) -> Result<(), BoxError> {
    debug!(name, "adding WFP callout");
    let mut name = WideString::new(name);
    let mut description = WideString::new(description);
    let mut provider_key = guid(WFP_PROVIDER_SAFECHAIN_L4_PROXY);
    let callout = FWPM_CALLOUT0 {
        calloutKey: guid(callout_key),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: 0,
        providerKey: &mut provider_key,
        providerData: zeroed_blob(),
        applicableLayer: layer_key,
        calloutId: 0,
    };

    let status = unsafe {
        // SAFETY: pointers remain valid for the duration of the call.
        FwpmCalloutAdd0(engine.0, &callout, ptr::null_mut(), ptr::null_mut())
    };
    check_status(status, "FwpmCalloutAdd0")
}

#[allow(clippy::too_many_arguments)]
fn add_filter(
    engine: &EngineHandle,
    filter_key: WindowsGuid,
    layer_key: windows_sys::core::GUID,
    callout_key: WindowsGuid,
    name: &str,
    description: &str,
    ip_protocol: u8,
    remote_port: Option<u16>,
    action_type: u32,
) -> Result<(), BoxError> {
    debug!(name, "adding WFP filter");
    let mut name = WideString::new(name);
    let mut description = WideString::new(description);
    let mut provider_key = guid(WFP_PROVIDER_SAFECHAIN_L4_PROXY);
    let protocol_condition_value = FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: ip_protocol },
    };
    let protocol_condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: protocol_condition_value,
    };
    let remote_port_condition = remote_port.map(|port| FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    });
    let mut conditions = [
        protocol_condition,
        remote_port_condition.unwrap_or(FWPM_FILTER_CONDITION0 {
            fieldKey: unsafe { core::mem::zeroed() },
            matchType: 0,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_EMPTY,
                Anonymous: unsafe { core::mem::zeroed() },
            },
        }),
    ];
    let (filter_condition, num_filter_conditions) = if remote_port_condition.is_some() {
        (conditions.as_mut_ptr(), 2)
    } else {
        (conditions.as_mut_ptr(), 1)
    };
    let filter = FWPM_FILTER0 {
        filterKey: guid(filter_key),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        },
        flags: 0,
        providerKey: &mut provider_key,
        providerData: zeroed_blob(),
        layerKey: layer_key,
        subLayerKey: guid(WFP_SUBLAYER_SAFECHAIN_L4_PROXY),
        weight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: unsafe { core::mem::zeroed() },
        },
        numFilterConditions: num_filter_conditions,
        filterCondition: filter_condition,
        action: FWPM_ACTION0 {
            r#type: action_type,
            Anonymous: FWPM_ACTION0_0 {
                calloutKey: guid(callout_key),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: ptr::null_mut(),
        filterId: 0,
        effectiveWeight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: unsafe { core::mem::zeroed() },
        },
    };

    let status = unsafe {
        // SAFETY: pointers remain valid for the duration of the call.
        FwpmFilterAdd0(engine.0, &filter, ptr::null_mut(), ptr::null_mut())
    };
    check_status(status, "FwpmFilterAdd0")
}

fn check_delete_status(
    status: u32,
    operation: &str,
    not_found_status: u32,
) -> Result<(), BoxError> {
    if status == ERROR_SUCCESS {
        debug!(operation, "WFP object removed");
        return Ok(());
    }

    if status == not_found_status {
        debug!(operation, "WFP object already absent");
        return Ok(());
    }

    warn!(
        operation,
        status = format_args!("{status:#x}"),
        "unexpected WFP delete failure"
    );
    Err(
        OpaqueError::from_static_str("WFP (delete) operation failed")
            .context_hex_field("status", status),
    )
}

fn zeroed_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: ptr::null_mut(),
    }
}

fn guid(parts: WindowsGuid) -> windows_sys::core::GUID {
    windows_sys::core::GUID {
        data1: parts.data1,
        data2: parts.data2,
        data3: parts.data3,
        data4: parts.data4,
    }
}

fn check_status(status: u32, operation: &str) -> Result<(), BoxError> {
    if status == ERROR_SUCCESS {
        debug!(operation, "WFP operation completed");
        Ok(())
    } else {
        warn!(
            operation,
            status = format_args!("{status:#x}"),
            "WFP operation failed"
        );
        Err(OpaqueError::from_static_str("WFP operation failed")
            .context_hex_field("status", status))
    }
}

struct EngineHandle(HANDLE);

impl EngineHandle {
    fn open() -> Result<Self, BoxError> {
        let mut engine: HANDLE = ptr::null_mut();
        let status = unsafe {
            // SAFETY: out pointer is valid; remaining pointers are null for local default auth.
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_DEFAULT,
                ptr::null(),
                ptr::null(),
                &mut engine,
            )
        };
        check_status(status, "FwpmEngineOpen0")?;
        Ok(Self(engine))
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // SAFETY: handle was opened by `FwpmEngineOpen0` and is closed once here.
                FwpmEngineClose0(self.0);
            }
        }
    }
}

struct Transaction<'a> {
    engine: &'a EngineHandle,
    committed: bool,
}

impl<'a> Transaction<'a> {
    fn begin(engine: &'a EngineHandle) -> Result<Self, BoxError> {
        let status = unsafe {
            // SAFETY: engine handle is valid for the lifetime of the transaction.
            FwpmTransactionBegin0(engine.0, 0)
        };
        check_status(status, "FwpmTransactionBegin0")?;
        Ok(Self {
            engine,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), BoxError> {
        let status = unsafe {
            // SAFETY: engine handle is valid and has an active transaction.
            FwpmTransactionCommit0(self.engine.0)
        };
        check_status(status, "FwpmTransactionCommit0")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                // SAFETY: aborting an open transaction is always valid during cleanup.
                FwpmTransactionAbort0(self.engine.0);
            }
        }
    }
}

struct WideString(Vec<u16>);

impl WideString {
    fn new(value: &str) -> Self {
        Self(value.encode_utf16().chain(Some(0)).collect())
    }

    fn as_mut_ptr(&mut self) -> *mut u16 {
        self.0.as_mut_ptr()
    }
}
