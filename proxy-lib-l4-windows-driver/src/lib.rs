#![cfg(target_os = "windows")]
#![no_std]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS};

mod control;
mod device;
mod driver;
mod log;
mod wfp;

pub use driver::{ProxyDriverConfigUpdate, ProxyDriverController, ProxyDriverStartupConfig};
pub use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY, IOCTL_SET_IPV6_PROXY,
};
pub use wfp::{TcpRedirectDecision, WfpFlowMeta};

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

static DRIVER: ProxyDriverController = ProxyDriverController::new();

pub fn driver_controller() -> &'static ProxyDriverController {
    &DRIVER
}

#[unsafe(export_name = "DriverEntry")]
/// Windows driver entrypoint.
///
/// # Safety
/// The OS loader invokes this with valid kernel pointers according to the WDM
/// `DriverEntry` contract. Callers must ensure `driver` and `registry_path`
/// obey that contract.
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    log::driver_log_info!(
        "driver entry invoked (runtime config required, redirect-target-pid enabled)"
    );
    driver.DriverUnload = Some(driver_unload);

    let init_status = control::initialize_runtime_config(&DRIVER, registry_path);
    if init_status != STATUS_SUCCESS {
        log::driver_log_error!(
            "runtime config initialization failed with NTSTATUS={:#x}",
            init_status
        );
        return init_status;
    }

    let device_status = device::initialize(driver);
    if device_status != STATUS_SUCCESS {
        log::driver_log_error!(
            "control device initialization failed with NTSTATUS={:#x}",
            device_status
        );
        return device_status;
    }

    let status = wfp::register_callouts(driver.DeviceObject.cast(), DRIVER.has_ipv6_proxy());
    if status != STATUS_SUCCESS {
        device::cleanup(driver);
        log::driver_log_error!(
            "WFP callout registration failed with NTSTATUS={:#x}",
            status
        );
        return status;
    }

    log::driver_log_info!(
        "driver initialized (runtime config required, redirect-target-pid enabled)"
    );
    STATUS_SUCCESS
}

/// Driver unload callback registered in `DriverEntry`.
extern "C" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    wfp::unregister_callouts();
    device::cleanup(_driver);
    DRIVER.clear_proxy_endpoint();
    log::driver_log_info!("driver unloaded (runtime config required, redirect-target-pid enabled)");
}

pub fn update_driver_config(update: ProxyDriverConfigUpdate) -> NTSTATUS {
    let status = control::apply_runtime_update(&DRIVER, update);
    if status != STATUS_SUCCESS {
        log::driver_log_warn!("runtime config update rejected with NTSTATUS={:#x}", status);
    }
    status
}

pub fn handle_device_control_ioctl(ioctl_code: u32, input: &[u8]) -> (NTSTATUS, u64) {
    control::ioctl::handle_device_control_ioctl(&DRIVER, ioctl_code, input)
}
