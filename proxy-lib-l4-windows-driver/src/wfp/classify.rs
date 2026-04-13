use core::{
    ffi::c_void,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
};

use crate::{driver_controller, log};

use super::{
    KernelCalloutRegistration, TcpRedirectDecision, UdpAuthConnectDecision, WfpFlowMeta,
    ffi::{
        FWP_ACTION_BLOCK, FWP_ACTION_CONTINUE, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16,
        FWP_BYTE_ARRAY16_TYPE, FWP_UINT16, FWP_UINT32, FWPS_CLASSIFY_OUT0, FWPS_CONNECT_REQUEST0,
        FWPS_CONNECTION_NOT_REDIRECTED, FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF,
        FWPS_CONNECTION_REDIRECTED_BY_OTHER, FWPS_CONNECTION_REDIRECTED_BY_SELF,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT, FWPS_FILTER1, FWPS_INCOMING_VALUES0,
        FWPS_LAYER_ALE_AUTH_CONNECT_V4, FWPS_LAYER_ALE_AUTH_CONNECT_V6,
        FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID, FWPS_METADATA_FIELD_ORIGINAL_DESTINATION,
        FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE, FWPS_RIGHT_ACTION_WRITE,
        FwpsAcquireClassifyHandle0, FwpsAcquireWritableLayerDataPointer0,
        FwpsApplyModifiedLayerData0, FwpsQueryConnectionRedirectState0, FwpsReleaseClassifyHandle0,
    },
    metadata::{incoming_metadata_values, source_pid_from_metadata, source_process_path_from_pid},
    sockaddr::{sockaddr_storage_to_socket_addr, write_socket_addr_to_storage},
};

pub(crate) unsafe extern "C" fn on_callout_classify(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const super::ffi::FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    classify_context: *const c_void,
    filter: *const FWPS_FILTER1,
    _flow_context: u64,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    let layer_id = incoming_layer_id(in_fixed_values);
    log::driver_log_info!("wfp: classify callback invoked (layer_id={:?})", layer_id);

    match layer_id.map(u32::from) {
        Some(id)
            if id == FWPS_LAYER_ALE_AUTH_CONNECT_V4 || id == FWPS_LAYER_ALE_AUTH_CONNECT_V6 =>
        {
            on_udp_auth_connect_classify(in_fixed_values, in_meta_values, classify_out);
            return;
        }
        _ => {}
    }

    let Some(context) = validate_tcp_classify(layer_data, classify_context, filter, classify_out)
    else {
        return;
    };

    if should_skip_redirect(in_meta_values, context.registration, classify_out) {
        return;
    }

    let Some(flow) = decode_tcp_flow_meta(in_meta_values, context.layer_data, classify_out) else {
        return;
    };
    let decision = driver_controller().classify_outbound_tcp_connect(flow);

    let TcpRedirectDecision::Redirect {
        proxy_target,
        proxy_target_pid,
        redirect_context,
    } = decision
    else {
        continue_action(classify_out);
        return;
    };

    apply_tcp_redirect(
        context,
        proxy_target,
        proxy_target_pid,
        &redirect_context,
        classify_out,
    );
}

struct TcpClassifyContext {
    layer_data: *mut c_void,
    classify_context: *const c_void,
    filter: *const FWPS_FILTER1,
    registration: KernelCalloutRegistration,
}

fn validate_tcp_classify(
    layer_data: *mut c_void,
    classify_context: *const c_void,
    filter: *const FWPS_FILTER1,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) -> Option<TcpClassifyContext> {
    if layer_data.is_null()
        || classify_context.is_null()
        || filter.is_null()
        || classify_out.is_null()
    {
        log::driver_log_warn!(
            "wfp: classify callback missing required pointers (layer_data_null={}, classify_context_null={}, filter_null={}, classify_out_null={})",
            layer_data.is_null(),
            classify_context.is_null(),
            filter.is_null(),
            classify_out.is_null(),
        );
        return None;
    }

    let registration = super::KERNEL_CALLOUT_REGISTRATION.lock().as_ref().copied();
    let Some(registration) = registration else {
        log::driver_log_warn!("wfp: classify callback invoked without callout registration");
        return None;
    };

    Some(TcpClassifyContext {
        layer_data,
        classify_context,
        filter,
        registration,
    })
}

fn should_skip_redirect(
    in_meta_values: *const super::ffi::FWPS_INCOMING_METADATA_VALUES0,
    registration: KernelCalloutRegistration,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) -> bool {
    let Some(state) = query_connection_redirect_state(in_meta_values, registration) else {
        return false;
    };

    match state.state {
        FWPS_CONNECTION_REDIRECTED_BY_SELF | FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF => {
            log::driver_log_info!("wfp: skip tcp redirect due to redirect state {state}");
            continue_action(classify_out);
            true
        }
        FWPS_CONNECTION_NOT_REDIRECTED | FWPS_CONNECTION_REDIRECTED_BY_OTHER => false,
        _ => {
            log::driver_log_warn!(
                "wfp: unknown redirect state {} (details: {state})",
                state.state
            );
            false
        }
    }
}

fn decode_tcp_flow_meta(
    in_meta_values: *const super::ffi::FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) -> Option<WfpFlowMeta> {
    let connect_request = layer_data.cast::<FWPS_CONNECT_REQUEST0>();
    let remote_storage = unsafe { &(*connect_request).remoteAddressAndPort };
    let remote = unsafe { sockaddr_storage_to_socket_addr(remote_storage) };
    let Some(remote) = remote else {
        let family = super::sockaddr::sockaddr_storage_family(remote_storage);
        log::driver_log_warn!(
            "wfp: classify could not decode remote address from SOCKADDR_STORAGE (family={:#x})",
            family
        );
        continue_action(classify_out);
        return None;
    };

    let source_pid = source_pid_from_metadata(in_meta_values);
    let source_process_path = source_pid.and_then(source_process_path_from_pid);
    log::driver_log_info!(
        "wfp: classify flow metadata (remote={}, source_pid={:?}, source_process_path={:?})",
        remote,
        source_pid,
        source_process_path,
    );

    Some(WfpFlowMeta {
        remote,
        source_pid,
        source_process_path,
    })
}

fn apply_tcp_redirect(
    context: TcpClassifyContext,
    proxy_target: SocketAddr,
    proxy_target_pid: u32,
    redirect_context: &[u8],
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    let mut classify_handle = 0_u64;
    let status = unsafe {
        FwpsAcquireClassifyHandle0(context.classify_context.cast_mut(), 0, &mut classify_handle)
    };
    if status != wdk_sys::STATUS_SUCCESS {
        log::driver_log_warn!("failed to acquire classify handle (status={:#x})", status);
        return;
    }

    let mut writable_layer_data = ptr::null_mut();
    let acquire_status = unsafe {
        FwpsAcquireWritableLayerDataPointer0(
            classify_handle,
            (*context.filter).filterId,
            0,
            &mut writable_layer_data,
            classify_out,
        )
    };
    if acquire_status != wdk_sys::STATUS_SUCCESS || writable_layer_data.is_null() {
        unsafe { FwpsReleaseClassifyHandle0(classify_handle) };
        if acquire_status != wdk_sys::STATUS_SUCCESS {
            log::driver_log_warn!(
                "failed to acquire writable layer data (status={:#x})",
                acquire_status
            );
        }
        return;
    }

    let writable_connect_request = writable_layer_data.cast::<FWPS_CONNECT_REQUEST0>();
    let context_ptr = super::allocate_redirect_context(redirect_context);
    if !redirect_context.is_empty() && context_ptr.is_null() {
        apply_and_release_writable_classify(classify_handle, writable_layer_data, classify_out);
        return;
    }

    unsafe {
        write_socket_addr_to_storage(
            &mut (*writable_connect_request).remoteAddressAndPort,
            proxy_target,
        );
        (*writable_connect_request).localRedirectTargetPID = proxy_target_pid;
        (*writable_connect_request).localRedirectHandle =
            context.registration.redirect_handle as *mut c_void;
        // Ownership handoff:
        // - before this assignment, `context_ptr` is driver-owned pool memory;
        // - after `FwpsApplyModifiedLayerData0` succeeds, WFP owns
        //   `localRedirectContext` and the proxy can read it back with
        //   `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`;
        // - there is no pre-handoff failure path after this assignment because
        //   the only remaining step is `FwpsApplyModifiedLayerData0`.
        (*writable_connect_request).localRedirectContext = context_ptr;
        (*writable_connect_request).localRedirectContextSize = redirect_context.len() as u64;

        if ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 {
            (*classify_out).actionType = FWP_ACTION_PERMIT;
            (*classify_out).rights &= !FWPS_RIGHT_ACTION_WRITE;
        }
    }

    apply_and_release_writable_classify(classify_handle, writable_layer_data, classify_out);
}

fn on_udp_auth_connect_classify(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const super::ffi::FWPS_INCOMING_METADATA_VALUES0,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    if classify_out.is_null() {
        log::driver_log_info!("wfp: on_udp_auth_connect_classify: classify out is null: ignore",);
        return;
    }

    let Some(remote) = auth_connect_remote(in_fixed_values) else {
        log::driver_log_info!(
            "wfp: on_udp_auth_connect_classify: no remote (socketaddr) found: ignore",
        );
        return;
    };
    let source_pid = source_pid_from_metadata(in_meta_values);
    let source_process_path = source_pid.and_then(source_process_path_from_pid);

    let decision = driver_controller().classify_outbound_udp_connect(WfpFlowMeta {
        remote,
        source_pid,
        source_process_path,
    });

    match decision {
        UdpAuthConnectDecision::Block => {
            log::driver_log_info!("wfp: on_udp_auth_connect_classify: block (remote = {remote})",);
            unsafe {
                if ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 {
                    (*classify_out).actionType = FWP_ACTION_BLOCK;
                    (*classify_out).rights &= !FWPS_RIGHT_ACTION_WRITE;
                } else {
                    log::driver_log_warn!(
                        "wfp: on_udp_auth_connect_classify: block decision could not be applied (missing FWPS_RIGHT_ACTION_WRITE; remote = {remote})",
                    );
                }
            }
        }
        UdpAuthConnectDecision::Passthrough => {
            log::driver_log_info!(
                "wfp: on_udp_auth_connect_classify: passthrough (remote = {remote})",
            );
        }
    }
}

fn auth_connect_remote(in_fixed_values: *const FWPS_INCOMING_VALUES0) -> Option<SocketAddr> {
    let fixed_values = unsafe { in_fixed_values.as_ref()? };
    let incoming_values = unsafe {
        core::slice::from_raw_parts(fixed_values.incomingValue, fixed_values.valueCount as usize)
    };

    match u32::from(fixed_values.layerId) {
        FWPS_LAYER_ALE_AUTH_CONNECT_V4 => {
            let addr = &incoming_values
                .get(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS)?
                .value;
            let port = &incoming_values
                .get(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT)?
                .value;
            let ip = unsafe {
                if addr.type_ != FWP_UINT32 || port.type_ != FWP_UINT16 {
                    return None;
                }
                Ipv4Addr::from(addr.__bindgen_anon_1.uint32.to_be_bytes())
            };
            let port = unsafe { port.__bindgen_anon_1.uint16 };
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        FWPS_LAYER_ALE_AUTH_CONNECT_V6 => {
            let addr = &incoming_values
                .get(FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS)?
                .value;
            let port = &incoming_values
                .get(FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT)?
                .value;
            let ip = unsafe {
                if addr.type_ != FWP_BYTE_ARRAY16_TYPE || port.type_ != FWP_UINT16 {
                    return None;
                }
                let bytes: &FWP_BYTE_ARRAY16 = addr.__bindgen_anon_1.byteArray16.as_ref()?;
                Ipv6Addr::from(bytes.byteArray16)
            };
            let port = unsafe { port.__bindgen_anon_1.uint16 };
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

fn incoming_layer_id(in_fixed_values: *const FWPS_INCOMING_VALUES0) -> Option<u16> {
    let fixed_values = unsafe { in_fixed_values.as_ref()? };
    Some(fixed_values.layerId)
}

fn continue_action(classify_out: *mut FWPS_CLASSIFY_OUT0) {
    unsafe {
        if !classify_out.is_null() && ((*classify_out).rights & FWPS_RIGHT_ACTION_WRITE) != 0 {
            (*classify_out).actionType = FWP_ACTION_CONTINUE;
        }
    }
}

fn apply_and_release_writable_classify(
    classify_handle: u64,
    writable_layer_data: *mut c_void,
    classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    unsafe {
        // `FwpsAcquireWritableLayerDataPointer0` requires the classify handle to
        // be completed with `FwpsApplyModifiedLayerData0`, even when we leave the
        // data unchanged. If a redirect context was attached to the writable
        // connect request, this is the point where ownership transfers to WFP.
        FwpsApplyModifiedLayerData0(classify_handle, writable_layer_data, 0);
        FwpsReleaseClassifyHandle0(classify_handle);
    }
    continue_action(classify_out);
}

struct RedirectState {
    state: i32,
    original_destination: Option<SocketAddr>,
    local_redirect_target_pid: Option<u32>,
}

impl RedirectState {
    fn fmt_fields(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "state={}, original_destination={:?}, local_redirect_target_pid={:?}",
            self.state, self.original_destination, self.local_redirect_target_pid
        )
    }
}

impl fmt::Display for RedirectState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_fields(f)
    }
}

fn query_connection_redirect_state(
    in_meta_values: *const super::ffi::FWPS_INCOMING_METADATA_VALUES0,
    registration: KernelCalloutRegistration,
) -> Option<RedirectState> {
    let metadata = incoming_metadata_values(in_meta_values)?;
    let (redirect_records, local_redirect_target_pid, original_destination) = unsafe {
        let metadata_ref = metadata.as_ref()?;
        let redirect_records = ((metadata_ref.currentMetadataValues
            & FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)
            != 0)
            .then_some(metadata_ref.redirectRecords)
            .filter(|records| !records.is_null());
        let local_redirect_target_pid = ((metadata_ref.currentMetadataValues
            & FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID)
            != 0)
            .then_some(metadata_ref.localRedirectTargetPID);
        let original_destination =
            if (metadata_ref.currentMetadataValues & FWPS_METADATA_FIELD_ORIGINAL_DESTINATION) != 0
                && !metadata_ref.originalDestination.is_null()
            {
                let storage = metadata_ref
                    .originalDestination
                    .cast::<super::ffi::SockAddrStorage>();
                storage
                    .as_ref()
                    .and_then(|storage| sockaddr_storage_to_socket_addr(storage))
            } else {
                None
            };
        (
            redirect_records,
            local_redirect_target_pid,
            original_destination,
        )
    };

    let redirect_records = redirect_records?;
    let mut redirect_context = ptr::null_mut();
    let state = unsafe {
        FwpsQueryConnectionRedirectState0(
            redirect_records,
            registration.redirect_handle as *mut c_void,
            &mut redirect_context,
        )
    };

    Some(RedirectState {
        state,
        original_destination,
        local_redirect_target_pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::ffi::{FWP_VALUE0, FWP_VALUE0_0, FWPS_INCOMING_VALUE0};

    #[test]
    fn auth_connect_remote_extracts_ipv4_endpoint() {
        let incoming = [
            empty_value(),
            empty_value(),
            empty_value(),
            empty_value(),
            empty_value(),
            empty_value(),
            FWPS_INCOMING_VALUE0 {
                value: FWP_VALUE0 {
                    type_: FWP_UINT32,
                    __bindgen_anon_1: FWP_VALUE0_0 {
                        uint32: u32::from_be_bytes([1, 1, 1, 1]),
                    },
                },
            },
            FWPS_INCOMING_VALUE0 {
                value: FWP_VALUE0 {
                    type_: FWP_UINT16,
                    __bindgen_anon_1: FWP_VALUE0_0 { uint16: 443 },
                },
            },
        ];
        let values = FWPS_INCOMING_VALUES0 {
            layerId: FWPS_LAYER_ALE_AUTH_CONNECT_V4 as u16,
            valueCount: incoming.len() as u32,
            incomingValue: incoming.as_ptr().cast_mut(),
        };

        let remote = auth_connect_remote(&values).expect("remote endpoint should parse");
        assert_eq!(
            remote,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443)
        );
    }

    #[test]
    fn auth_connect_remote_extracts_ipv6_endpoint() {
        let mut ipv6 = FWP_BYTE_ARRAY16 {
            byteArray16: [0u8; 16],
        };
        ipv6.byteArray16[0] = 0x26;
        ipv6.byteArray16[1] = 0x06;
        ipv6.byteArray16[2] = 0x47;
        ipv6.byteArray16[3] = 0x00;
        ipv6.byteArray16[15] = 0x11;

        let incoming = [
            empty_value(),
            empty_value(),
            empty_value(),
            empty_value(),
            empty_value(),
            empty_value(),
            FWPS_INCOMING_VALUE0 {
                value: FWP_VALUE0 {
                    type_: FWP_BYTE_ARRAY16_TYPE,
                    __bindgen_anon_1: FWP_VALUE0_0 {
                        byteArray16: &mut ipv6,
                    },
                },
            },
            FWPS_INCOMING_VALUE0 {
                value: FWP_VALUE0 {
                    type_: FWP_UINT16,
                    __bindgen_anon_1: FWP_VALUE0_0 { uint16: 443 },
                },
            },
        ];
        let values = FWPS_INCOMING_VALUES0 {
            layerId: FWPS_LAYER_ALE_AUTH_CONNECT_V6 as u16,
            valueCount: incoming.len() as u32,
            incomingValue: incoming.as_ptr().cast_mut(),
        };

        let remote = auth_connect_remote(&values).expect("remote endpoint should parse");
        assert_eq!(
            remote,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x0011)),
                443
            )
        );
    }

    fn empty_value() -> FWPS_INCOMING_VALUE0 {
        FWPS_INCOMING_VALUE0 {
            value: FWP_VALUE0 {
                type_: 0,
                __bindgen_anon_1: FWP_VALUE0_0 {
                    uint64: core::ptr::null_mut(),
                },
            },
        }
    }
}
