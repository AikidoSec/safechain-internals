use core::sync::atomic::{AtomicBool, Ordering};

use wdk_sys::{
    BOOLEAN, HANDLE, NTSTATUS, PEPROCESS, PPS_CREATE_NOTIFY_INFO, STATUS_SUCCESS,
    ntddk::PsSetCreateProcessNotifyRoutineEx,
};

use crate::{driver_controller, log};

static PROCESS_MONITOR_REGISTERED: AtomicBool = AtomicBool::new(false);

pub fn register() -> NTSTATUS {
    if PROCESS_MONITOR_REGISTERED.swap(true, Ordering::AcqRel) {
        return STATUS_SUCCESS;
    }

    let status = unsafe {
        // SAFETY: callback has a stable address for the lifetime of the driver.
        PsSetCreateProcessNotifyRoutineEx(Some(on_process_notify), false as BOOLEAN)
    };
    if status != STATUS_SUCCESS {
        PROCESS_MONITOR_REGISTERED.store(false, Ordering::Release);
        return status;
    }

    log::driver_log_info!("process monitor registered");
    STATUS_SUCCESS
}

pub fn unregister() -> NTSTATUS {
    if !PROCESS_MONITOR_REGISTERED.swap(false, Ordering::AcqRel) {
        return STATUS_SUCCESS;
    }

    let status = unsafe {
        // SAFETY: callback was registered through the matching API above.
        PsSetCreateProcessNotifyRoutineEx(Some(on_process_notify), true as BOOLEAN)
    };

    if status == STATUS_SUCCESS {
        log::driver_log_info!("process monitor unregistered");
    } else {
        PROCESS_MONITOR_REGISTERED.store(true, Ordering::Release);
        log::driver_log_warn!(
            "process monitor unregister failed with NTSTATUS={:#x}",
            status
        );
    }

    status
}

unsafe extern "C" fn on_process_notify(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let Some(pid) = handle_to_pid(process_id) else {
        return;
    };

    if create_info.is_null() {
        driver_controller().handle_process_exit(pid);
    }
}

fn handle_to_pid(handle: HANDLE) -> Option<u32> {
    let raw = handle as usize;
    u32::try_from(raw).ok()
}
