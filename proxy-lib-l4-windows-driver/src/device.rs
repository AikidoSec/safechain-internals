use core::ptr;

use safechain_proxy_lib_nostd::windows::unicode::{unicode_from_wide_mut, utf16_null_terminated};

use wdk_sys::{
    DRIVER_OBJECT, IO_NO_INCREMENT, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, NTSTATUS,
    PDEVICE_OBJECT, PIRP, STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS,
    ntddk::{
        IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
        IofCompleteRequest,
    },
};

use crate::log;

const DEVICE_NAME: &str = "\\Device\\SafechainL4Proxy";
const DEVICE_SYMBOLIC_LINK: &str = "\\??\\SafechainL4Proxy";

/// `METHOD_BUFFERED` from `devioctl.h`.
///
/// For `IRP_MJ_DEVICE_CONTROL`, the transfer method is encoded in the low two
/// bits of the IOCTL value (`METHOD_FROM_CTL_CODE(ctrlCode) == ctrlCode & 3`).
/// Microsoft documents `METHOD_BUFFERED` as value `0`.
/// Docs:
/// - https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-based-ioctl-and-fsctl-operations
/// - https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
/// - https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
const METHOD_BUFFERED: u32 = 0;

#[inline(always)]
fn ioctl_transfer_method(ioctl_code: u32) -> u32 {
    ioctl_code & 0x3
}

/// Initialize kernel control device + symbolic link and wire dispatch table.
///
/// WDK references (`ntddk.h`):
/// - `IoCreateDevice`:
///   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice
/// - `IoCreateSymbolicLink`:
///   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatesymboliclink
pub fn initialize(driver: &mut DRIVER_OBJECT) -> NTSTATUS {
    let mut device_name_w = utf16_null_terminated(DEVICE_NAME);
    let mut device_name = unicode_from_wide_mut(&mut device_name_w);

    let mut device_object: PDEVICE_OBJECT = ptr::null_mut();
    let status = unsafe {
        // SAFETY: pointers are valid for the duration of the call; output pointer is valid.
        IoCreateDevice(
            driver,
            0,
            &mut device_name,
            wdk_sys::FILE_DEVICE_UNKNOWN,
            0,
            0,
            &mut device_object,
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }

    let mut symlink_w = utf16_null_terminated(DEVICE_SYMBOLIC_LINK);
    let mut symlink = unicode_from_wide_mut(&mut symlink_w);
    let sym_status = unsafe {
        // SAFETY: pointers are valid for the duration of the call.
        IoCreateSymbolicLink(&mut symlink, &mut device_name)
    };
    if sym_status != STATUS_SUCCESS {
        unsafe {
            // SAFETY: device object was successfully created by IoCreateDevice.
            IoDeleteDevice(device_object);
        }
        return sym_status;
    }

    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);

    STATUS_SUCCESS
}

/// Tear down symbolic link and device object.
pub fn cleanup(driver: *mut DRIVER_OBJECT) {
    let mut symlink_w = utf16_null_terminated(DEVICE_SYMBOLIC_LINK);
    let mut symlink = unicode_from_wide_mut(&mut symlink_w);
    unsafe {
        // SAFETY: symbolic link path points to static string bytes owned in this function scope.
        let _ = IoDeleteSymbolicLink(&mut symlink);
        if !driver.is_null() && !(*driver).DeviceObject.is_null() {
            // SAFETY: DriverObject->DeviceObject was created by IoCreateDevice and may be null if init failed.
            IoDeleteDevice((*driver).DeviceObject);
        }
    }
}

/// IRP dispatch handler for `IRP_MJ_CREATE` / `IRP_MJ_CLOSE`.
extern "C" fn dispatch_create_close(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    complete_request(irp, STATUS_SUCCESS, 0)
}

/// IRP dispatch handler for `IRP_MJ_DEVICE_CONTROL`.
extern "C" fn dispatch_device_control(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let irp_sp = unsafe {
        // SAFETY: IRP is provided by I/O manager for dispatch callback.
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    if irp_sp.is_null() {
        return complete_request(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }

    let dic = unsafe { (*irp_sp).Parameters.DeviceIoControl };
    // Our private IOCTLs are defined with METHOD_BUFFERED, so `SystemBuffer` is
    // only valid when the transfer method extracted from the IOCTL is `0`.
    if ioctl_transfer_method(dic.IoControlCode) != METHOD_BUFFERED {
        log::driver_log_warn!(
            "device control request rejected due to unsupported transfer method (ioctl={:#x})",
            dic.IoControlCode
        );
        return complete_request(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }

    let input_len = dic.InputBufferLength as usize;
    let input = unsafe {
        // SAFETY: for METHOD_BUFFERED, SystemBuffer points to input/output buffer owned by I/O manager.
        if input_len == 0 || (*irp).AssociatedIrp.SystemBuffer.is_null() {
            &[]
        } else {
            core::slice::from_raw_parts((*irp).AssociatedIrp.SystemBuffer.cast::<u8>(), input_len)
        }
    };

    let (status, bytes_out) = crate::handle_device_control_ioctl(dic.IoControlCode, input);
    if status != STATUS_SUCCESS {
        log::driver_log_warn!(
            "device control request failed (ioctl={:#x}, status={:#x})",
            dic.IoControlCode,
            status
        );
    }

    complete_request(irp, status, bytes_out)
}

/// Complete a request with status/info and hand it back to the I/O manager.
///
/// WDK references (`ntddk.h`):
/// - `IoCompleteRequest`:
///   https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest
fn complete_request(irp: PIRP, status: NTSTATUS, info: u64) -> NTSTATUS {
    unsafe {
        // SAFETY: IRP is valid for this dispatch invocation and completion path.
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = info;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    }
    status
}
