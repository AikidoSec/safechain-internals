use super::*;

pub fn handle_device_control_ioctl(
    controller: &ProxyDriverController,
    ioctl_code: u32,
    input: &[u8],
) -> (NTSTATUS, u64) {
    let update = match ioctl_code {
        IOCTL_SET_IPV4_PROXY => parse_ipv4_update(input),
        IOCTL_SET_IPV6_PROXY => parse_ipv6_update(input),
        IOCTL_CLEAR_IPV6_PROXY => Some(ProxyDriverConfigUpdate::SetIpv6 {
            proxy: None,
            pid: None,
        }),
        _ => None,
    };

    let Some(update) = update else {
        return (STATUS_INVALID_PARAMETER, 0);
    };

    let status = super::apply_runtime_update(controller, update);
    (status, 0)
}

fn parse_ipv4_update(input: &[u8]) -> Option<ProxyDriverConfigUpdate> {
    let payload = Ipv4ProxyConfigPayload::from_bytes(input)?;
    Some(ProxyDriverConfigUpdate::SetIpv4 {
        proxy: payload.socket_addr(),
        pid: payload.pid(),
    })
}

fn parse_ipv6_update(input: &[u8]) -> Option<ProxyDriverConfigUpdate> {
    let payload = Ipv6ProxyConfigPayload::from_bytes(input)?;
    Some(ProxyDriverConfigUpdate::SetIpv6 {
        proxy: Some(payload.socket_addr()),
        pid: Some(payload.pid()),
    })
}

#[cfg(test)]
#[path = "ioctl_tests.rs"]
mod tests;
