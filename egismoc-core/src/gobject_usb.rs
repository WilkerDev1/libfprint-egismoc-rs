//! Adaptador GObject + USB 100% en Rust para `libfprint`.
//!
//! Reemplaza por completo el antiguo puente en C (`c-bridge/egismoc.c` y `c-bridge/egismoc.h`).
//! Exporta directamente el único punto de entrada que `libfprint` requiere para registrar el
//! driver (`fpi_device_egismoc_get_type`), gestiona el ciclo de vida de `FpiDeviceEgisMoc`,
//! despacha transferencias USB (`Control`, `Bulk`, `Interrupt`) mediante `FpiUsbTransfer`
//! y delega toda la lógica de protocolo y criptografía SDCP a `EgisMocDriver` (Sans-I/O).

use crate::glib_ffi::*;
use crate::is_emulation_mode;
use crate::protocol::{
    CaptureReadStatus, EGISMOC_DRIVER_CHECK_PREFIX_TYPE1, EGISMOC_DRIVER_CHECK_PREFIX_TYPE2,
    EGISMOC_DRIVER_MAX_ENROLL_STAGES_15, EGISMOC_DRIVER_MAX_ENROLL_STAGES_20, EGISMOC_EP_CMD_IN,
    EGISMOC_EP_CMD_INTERRUPT_IN, EGISMOC_EP_CMD_OUT, EGISMOC_MAX_ENROLL_STAGES_DEFAULT,
    EGISMOC_USB_CONTROL_TIMEOUT, EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH,
    EGISMOC_USB_INTERRUPT_TIMEOUT, EGISMOC_USB_IN_RECV_LENGTH, EGISMOC_USB_RECV_TIMEOUT,
    EGISMOC_USB_SEND_TIMEOUT,
};
use crate::sdcp::{IdentityVerification, SdcpSession, SDCP_ENROLLMENT_ID_SIZE};
use crate::state::{Action, DriverError, EgisMocDriver, EnrollProgress, TaskResult};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::mem::size_of;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

const EGISMOC_FINGER_ON_SENSOR_TIMEOUT_USEC: gint64 = 10 * 1_000_000;
const LOG_DOMAIN: &CStr = c"libfprint-egismoc";

/// Instancia GObject `FpiDeviceEgisMoc` que hereda directamente de `FpDevice`.
#[repr(C)]
struct FpiDeviceEgisMoc {
    parent: FpDevice,
    driver: *mut EgisMocDriver,
    wait_finger_start: gint64,
    interrupt_cancellable: *mut GCancellable,
}

static EGISMOC_TYPE: OnceLock<GType> = OnceLock::new();
static PARENT_CLASS: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// Tabla de dispositivos USB soportados (Egis Technology Match-on-Chip `1c7a:0582` – `1c7a:05a5`).
static EGISMOC_ID_TABLE: [FpIdEntry; 8] = [
    FpIdEntry::usb(0x1c7a, 0x0582, EGISMOC_DRIVER_CHECK_PREFIX_TYPE1),
    FpIdEntry::usb(
        0x1c7a,
        0x0583,
        EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_15,
    ),
    FpIdEntry::usb(
        0x1c7a,
        0x0584,
        EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20,
    ),
    FpIdEntry::usb(
        0x1c7a,
        0x0586,
        EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20,
    ),
    FpIdEntry::usb(
        0x1c7a,
        0x0587,
        EGISMOC_DRIVER_CHECK_PREFIX_TYPE1 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_20,
    ),
    FpIdEntry::usb(0x1c7a, 0x05a1, EGISMOC_DRIVER_CHECK_PREFIX_TYPE2),
    FpIdEntry::usb(
        0x1c7a,
        0x05a5,
        EGISMOC_DRIVER_CHECK_PREFIX_TYPE2 | EGISMOC_DRIVER_MAX_ENROLL_STAGES_15,
    ),
    FpIdEntry::terminator(),
];

/// Punto de entrada GObject requerido por `libfprint` (`fpi-drivers.c`).
#[no_mangle]
pub extern "C" fn fpi_device_egismoc_get_type() -> GType {
    *EGISMOC_TYPE.get_or_init(|| unsafe {
        let type_name = g_intern_static_string(c"FpiDeviceEgisMoc".as_ptr());
        g_type_register_static_simple(
            fp_device_get_type(),
            type_name,
            size_of::<FpDeviceClass>() as guint,
            Some(fpi_device_egismoc_class_init),
            size_of::<FpiDeviceEgisMoc>() as guint,
            Some(fpi_device_egismoc_init),
            0,
        )
    })
}

#[inline]
unsafe fn as_egismoc<'a>(device: *mut FpDevice) -> &'a mut FpiDeviceEgisMoc {
    &mut *(device as *mut FpiDeviceEgisMoc)
}

unsafe fn ensure_driver<'a>(device: *mut FpDevice) -> &'a mut EgisMocDriver {
    let self_dev = as_egismoc(device);
    if self_dev.driver.is_null() {
        let driver_data = fpi_device_get_driver_data(device);
        let boxed = Box::new(EgisMocDriver::from_driver_data(driver_data));
        self_dev.driver = Box::into_raw(boxed);
    }

    let drv = &mut *self_dev.driver;
    let dev_id_ptr = fp_device_get_device_id(device);
    let drv_name_ptr = fp_device_get_driver(device);
    if !dev_id_ptr.is_null() && !drv_name_ptr.is_null() {
        if let (Ok(drv_str), Ok(dev_str)) = (
            CStr::from_ptr(drv_name_ptr).to_str(),
            CStr::from_ptr(dev_id_ptr).to_str(),
        ) {
            let path = SdcpSession::default_claim_cache_path(drv_str, dev_str);
            drv.sdcp.set_claim_cache_path(path);
        }
    }

    drv
}

unsafe fn clear_cancellable(slot: &mut *mut GCancellable) {
    if !slot.is_null() {
        let obj = *slot;
        *slot = ptr::null_mut();
        g_object_unref(obj as gpointer);
    }
}

unsafe fn set_print_data(print: *mut FpPrint, enrollment_id: &[u8; SDCP_ENROLLMENT_ID_SIZE]) {
    fpi_print_set_type(print, FPI_PRINT_RAW);
    fpi_print_set_device_stored(print, GTRUE);

    let byte_type = c"y".as_ptr() as *const GVariantType;
    let id_var = g_variant_new_fixed_array(
        byte_type,
        enrollment_id.as_ptr() as gconstpointer,
        SDCP_ENROLLMENT_ID_SIZE,
        1,
    );
    let children = [id_var];
    let fpi_data = g_variant_new_tuple(children.as_ptr(), 1);
    g_object_set(
        print as gpointer,
        c"fpi-data".as_ptr(),
        fpi_data,
        ptr::null_mut::<c_void>(),
    );
}

unsafe fn map_driver_error(err: DriverError) -> *mut GError {
    match err {
        DriverError::General(msg) => {
            log_dbg(msg);
            fpi_device_error_new(FP_DEVICE_ERROR_GENERAL)
        }
        DriverError::Proto(msg) => {
            log_dbg(msg);
            fpi_device_error_new(FP_DEVICE_ERROR_PROTO)
        }
        DriverError::DataInvalid(msg) => {
            log_dbg(msg);
            fpi_device_error_new(FP_DEVICE_ERROR_DATA_INVALID)
        }
        DriverError::DataNotFound(msg) => {
            log_dbg(msg);
            fpi_device_error_new(FP_DEVICE_ERROR_DATA_NOT_FOUND)
        }
        DriverError::DataFull => fpi_device_error_new(FP_DEVICE_ERROR_DATA_FULL),
        DriverError::DataDuplicate => fpi_device_error_new(FP_DEVICE_ERROR_DATA_DUPLICATE),
    }
}

unsafe fn log_dbg(msg: &str) {
    g_log(
        LOG_DOMAIN.as_ptr(),
        G_LOG_LEVEL_DEBUG,
        c"%.*s".as_ptr(),
        msg.len() as gint,
        msg.as_ptr() as *const c_char,
    );
}

unsafe fn fail_current_action(device: *mut FpDevice, error: *mut GError) {
    if device.is_null() {
        if !error.is_null() {
            g_error_free(error);
        }
        return;
    }

    let self_dev = as_egismoc(device);
    self_dev.wait_finger_start = 0;
    if !self_dev.driver.is_null() {
        (*self_dev.driver).cancel();
    }

    let action = fpi_device_get_current_action(device);
    if action == FPI_DEVICE_ACTION_OPEN {
        let usb_dev = fpi_device_get_usb_device(device);
        g_usb_device_release_interface(usb_dev, 0, 0, ptr::null_mut());
    }

    if action != FPI_DEVICE_ACTION_NONE {
        fpi_device_action_error(device, error);
    } else if !error.is_null() {
        g_error_free(error);
    }
}

unsafe fn fail_cancelled(device: *mut FpDevice) {
    let err = g_error_new_literal(
        g_io_error_quark(),
        G_IO_ERROR_CANCELLED,
        c"Operation was cancelled".as_ptr(),
    );
    fail_current_action(device, err);
}

unsafe extern "C" fn fp_print_equal_trampoline(a: gconstpointer, b: gconstpointer) -> gboolean {
    fp_print_equal(a as *mut FpPrint, b as *mut FpPrint)
}

unsafe extern "C" fn egismoc_usb_rx_cb(
    transfer: *mut FpiUsbTransfer,
    device: *mut FpDevice,
    _userdata: gpointer,
    error: *mut GError,
) {
    if !error.is_null() {
        fail_current_action(device, error);
        return;
    }

    if fpi_device_action_is_cancelled(device) != GFALSE {
        fail_cancelled(device);
        return;
    }

    if transfer.is_null() || (*transfer).actual_length < 0 {
        fail_current_action(device, fpi_device_error_new(FP_DEVICE_ERROR_PROTO));
        return;
    }

    let actual_len = (*transfer).actual_length as usize;
    let rx_slice = if actual_len == 0 {
        &[]
    } else if (*transfer).buffer.is_null() {
        fail_current_action(device, fpi_device_error_new(FP_DEVICE_ERROR_PROTO));
        return;
    } else {
        slice::from_raw_parts((*transfer).buffer, actual_len)
    };

    drive_rust(device, Some(rx_slice));
}

unsafe extern "C" fn egismoc_cmd_tx_done_cb(
    _transfer: *mut FpiUsbTransfer,
    device: *mut FpDevice,
    _userdata: gpointer,
    error: *mut GError,
) {
    if !error.is_null() {
        fail_current_action(device, error);
        return;
    }

    if fpi_device_action_is_cancelled(device) != GFALSE {
        fail_cancelled(device);
        return;
    }

    let rx_transfer = fpi_usb_transfer_new(device);
    fpi_usb_transfer_fill_bulk(
        rx_transfer,
        EGISMOC_EP_CMD_IN | FPI_USB_ENDPOINT_IN,
        EGISMOC_USB_IN_RECV_LENGTH,
    );
    fpi_usb_transfer_submit(
        rx_transfer,
        EGISMOC_USB_RECV_TIMEOUT,
        fpi_device_get_cancellable(device),
        Some(egismoc_usb_rx_cb),
        ptr::null_mut(),
    );
}

unsafe fn wait_finger_on_sensor(device: *mut FpDevice) {
    let self_dev = as_egismoc(device);
    let now = g_get_monotonic_time();

    if self_dev.wait_finger_start == 0 {
        self_dev.wait_finger_start = now;
        fpi_device_report_finger_status(device, FP_FINGER_STATUS_NEEDED);
    }

    if self_dev.wait_finger_start + EGISMOC_FINGER_ON_SENSOR_TIMEOUT_USEC <= now {
        let err = fpi_device_error_new_msg(
            FP_DEVICE_ERROR_GENERAL,
            c"Timed out trying to detect finger on sensor".as_ptr(),
        );
        fail_current_action(device, err);
        return;
    }

    let transfer = fpi_usb_transfer_new(device);
    fpi_usb_transfer_fill_interrupt(
        transfer,
        EGISMOC_EP_CMD_INTERRUPT_IN,
        EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH,
    );
    (*transfer).short_is_error = GFALSE;

    fpi_usb_transfer_submit(
        transfer,
        EGISMOC_USB_INTERRUPT_TIMEOUT,
        self_dev.interrupt_cancellable,
        Some(egismoc_usb_rx_cb),
        ptr::null_mut(),
    );
}

unsafe fn report_enroll_progress(device: *mut FpDevice, progress: Option<&EnrollProgress>) {
    let Some(prog) = progress else {
        return;
    };

    let mut enroll_print: *mut FpPrint = ptr::null_mut();
    fpi_device_get_enroll_data(device, &mut enroll_print);

    match prog.status {
        CaptureReadStatus::Success => {
            fpi_device_enroll_progress(
                device,
                prog.completed_stages,
                enroll_print,
                ptr::null_mut(),
            );
        }
        CaptureReadStatus::OffCenter => {
            let retry_err = fpi_device_retry_new(FP_DEVICE_RETRY_CENTER_FINGER);
            fpi_device_enroll_progress(device, prog.completed_stages, ptr::null_mut(), retry_err);
        }
        CaptureReadStatus::DirtySensor => {
            let retry_err = fpi_device_retry_new_msg(
                FP_DEVICE_RETRY_REMOVE_FINGER,
                c"Your device is having trouble recognizing you. Make sure your sensor is clean."
                    .as_ptr(),
            );
            fpi_device_enroll_progress(device, prog.completed_stages, ptr::null_mut(), retry_err);
        }
        CaptureReadStatus::RetryUnknown => {
            let retry_err = fpi_device_retry_new_msg(
                FP_DEVICE_RETRY_REMOVE_FINGER,
                c"Unknown failure trying to read your finger. Please try again.".as_ptr(),
            );
            fpi_device_enroll_progress(device, prog.completed_stages, ptr::null_mut(), retry_err);
        }
    }
}

unsafe fn handle_task_complete(device: *mut FpDevice, result: TaskResult) {
    let self_dev = as_egismoc(device);
    self_dev.wait_finger_start = 0;

    match result {
        TaskResult::ProbeComplete { .. } => {
            fpi_device_open_complete(device, ptr::null_mut());
        }
        TaskResult::ListComplete { enrolled_ids } => {
            let list = g_ptr_array_new_with_free_func(Some(g_object_unref));
            for id in &enrolled_ids {
                let print = fp_print_new(device);
                set_print_data(print, id);
                g_ptr_array_add(list, g_object_ref_sink(print as gpointer));
            }
            fpi_device_list_complete(device, list, ptr::null_mut());
        }
        TaskResult::IdentifyComplete {
            matched_enrollment_id,
            verification,
        } => {
            if let Some(id) = matched_enrollment_id {
                let print = fp_print_new(device);
                set_print_data(print, &id);

                if verification == Some(IdentityVerification::MacMismatchAfterReset) {
                    log_dbg(
                        "SDCP AuthorizedIdentity MAC mismatch after USB reset; relying on enrollment_id match",
                    );
                }

                if fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_IDENTIFY {
                    let mut prints: *mut GPtrArray = ptr::null_mut();
                    let mut index: guint = 0;
                    fpi_device_get_identify_data(device, &mut prints);
                    if !prints.is_null()
                        && g_ptr_array_find_with_equal_func(
                            prints,
                            print as gconstpointer,
                            Some(fp_print_equal_trampoline),
                            &mut index,
                        ) != GFALSE
                    {
                        let matched_ptr = *(*prints).pdata.add(index as usize) as *mut FpPrint;
                        fpi_device_identify_report(device, matched_ptr, print, ptr::null_mut());
                    } else {
                        fpi_device_identify_report(device, ptr::null_mut(), print, ptr::null_mut());
                    }
                    fpi_device_identify_complete(device, ptr::null_mut());
                } else {
                    let mut verify_print: *mut FpPrint = ptr::null_mut();
                    fpi_device_get_verify_data(device, &mut verify_print);
                    if !verify_print.is_null() && fp_print_equal(verify_print, print) != GFALSE {
                        fpi_device_verify_report(device, FPI_MATCH_SUCCESS, print, ptr::null_mut());
                    } else {
                        fpi_device_verify_report(device, FPI_MATCH_FAIL, print, ptr::null_mut());
                    }
                    fpi_device_verify_complete(device, ptr::null_mut());
                }
            } else if fpi_device_get_current_action(device) == FPI_DEVICE_ACTION_VERIFY {
                fpi_device_verify_report(device, FPI_MATCH_FAIL, ptr::null_mut(), ptr::null_mut());
                fpi_device_verify_complete(device, ptr::null_mut());
            } else {
                fpi_device_identify_report(
                    device,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                fpi_device_identify_complete(device, ptr::null_mut());
            }
        }
        TaskResult::EnrollComplete { enrollment_id } => {
            let mut enroll_print: *mut FpPrint = ptr::null_mut();
            fpi_device_get_enroll_data(device, &mut enroll_print);
            set_print_data(enroll_print, &enrollment_id);
            fpi_device_enroll_complete(
                device,
                g_object_ref(enroll_print as gpointer) as *mut FpPrint,
                ptr::null_mut(),
            );
        }
        TaskResult::DeleteComplete => {
            fpi_device_delete_complete(device, ptr::null_mut());
        }
        TaskResult::ClearStorageComplete => {
            fpi_device_clear_storage_complete(device, ptr::null_mut());
        }
    }
}

unsafe fn drive_rust(device: *mut FpDevice, rx: Option<&[u8]>) {
    let action = {
        let drv = ensure_driver(device);
        drv.step(rx)
    };

    match action {
        Action::Idle => {
            // Si la tarea interna fue cancelada pero libfprint aún espera la finalización de la
            // acción en curso (carrera entre cancelación y callback USB), completamos con
            // G_IO_ERROR_CANCELLED para no colgar nunca fprintd.
            if fpi_device_get_current_action(device) != FPI_DEVICE_ACTION_NONE {
                fail_cancelled(device);
            }
        }
        Action::ControlTransfer {
            direction,
            request_type,
            recipient,
            request,
            value,
            index,
            length,
        } => {
            let transfer = fpi_usb_transfer_new(device);
            (*transfer).short_is_error = GTRUE;
            fpi_usb_transfer_fill_control(
                transfer,
                direction as c_int,
                request_type as c_int,
                recipient as c_int,
                request,
                value,
                index,
                length,
            );
            fpi_usb_transfer_submit(
                transfer,
                EGISMOC_USB_CONTROL_TIMEOUT,
                fpi_device_get_cancellable(device),
                Some(egismoc_usb_rx_cb),
                ptr::null_mut(),
            );
        }
        Action::SendCommand {
            packet,
            finger_present,
            enroll_progress,
        } => {
            if finger_present {
                as_egismoc(device).wait_finger_start = 0;
                fpi_device_report_finger_status(device, FP_FINGER_STATUS_PRESENT);
            }

            report_enroll_progress(device, enroll_progress.as_ref());

            let tx_copy = g_memdup2(packet.as_ptr() as gconstpointer, packet.len()) as *mut guint8;
            let transfer = fpi_usb_transfer_new(device);
            (*transfer).short_is_error = GTRUE;
            fpi_usb_transfer_fill_bulk_full(
                transfer,
                EGISMOC_EP_CMD_OUT | FPI_USB_ENDPOINT_OUT,
                tx_copy,
                packet.len(),
                Some(g_free),
            );
            fpi_usb_transfer_submit(
                transfer,
                EGISMOC_USB_SEND_TIMEOUT,
                fpi_device_get_cancellable(device),
                Some(egismoc_cmd_tx_done_cb),
                ptr::null_mut(),
            );
        }
        Action::WaitFingerOnSensor { enroll_progress } => {
            report_enroll_progress(device, enroll_progress.as_ref());
            wait_finger_on_sensor(device);
        }
        Action::TaskComplete(result) => {
            handle_task_complete(device, result);
        }
        Action::Error(err) => {
            fail_current_action(device, map_driver_error(err));
        }
    }
}

unsafe extern "C" fn egismoc_probe(device: *mut FpDevice) {
    let max_stages = ensure_driver(device).max_enroll_stages;
    let usb_dev = fpi_device_get_usb_device(device);
    let mut error: *mut GError = ptr::null_mut();

    if g_usb_device_open(usb_dev, &mut error) == GFALSE {
        fpi_device_probe_complete(device, ptr::null(), ptr::null(), error);
        return;
    }

    if g_usb_device_reset(usb_dev, &mut error) == GFALSE {
        g_usb_device_close(usb_dev, ptr::null_mut());
        fpi_device_probe_complete(device, ptr::null(), ptr::null(), error);
        return;
    }

    if g_usb_device_claim_interface(usb_dev, 0, 0, &mut error) == GFALSE {
        g_usb_device_close(usb_dev, ptr::null_mut());
        fpi_device_probe_complete(device, ptr::null(), ptr::null(), error);
        return;
    }

    let serial = if is_emulation_mode() {
        g_strdup(c"emulated-device".as_ptr())
    } else {
        let idx = g_usb_device_get_serial_number_index(usb_dev);
        g_usb_device_get_string_descriptor(usb_dev, idx, &mut error)
    };

    if !error.is_null() {
        if !serial.is_null() {
            g_free(serial as gpointer);
        }
        g_usb_device_release_interface(usb_dev, 0, 0, ptr::null_mut());
        g_usb_device_close(usb_dev, ptr::null_mut());
        fpi_device_probe_complete(device, ptr::null(), ptr::null(), error);
        return;
    }

    fpi_device_set_nr_enroll_stages(device, max_stages);

    g_usb_device_release_interface(usb_dev, 0, 0, ptr::null_mut());
    g_usb_device_close(usb_dev, ptr::null_mut());

    fpi_device_probe_complete(device, serial, ptr::null(), ptr::null_mut());
    if !serial.is_null() {
        g_free(serial as gpointer);
    }
}

unsafe extern "C" fn egismoc_open(device: *mut FpDevice) {
    let mut error: *mut GError = ptr::null_mut();

    let _ = ensure_driver(device);
    let self_dev = as_egismoc(device);
    self_dev.wait_finger_start = 0;
    clear_cancellable(&mut self_dev.interrupt_cancellable);
    self_dev.interrupt_cancellable = g_cancellable_new();

    let usb_dev = fpi_device_get_usb_device(device);
    if g_usb_device_reset(usb_dev, &mut error) == GFALSE {
        fpi_device_open_complete(device, error);
        return;
    }

    // Tras g_usb_device_reset() en hardware real, el sensor borra su sesión SDCP volátil en RAM.
    // Invalidamos el caché local para forzar un handshake SDCP Connect limpio y lograr verificación
    // criptográfica completa en el primer intento (conservando el comportamiento en emulación).
    ensure_driver(device).invalidate_sdcp_on_hardware_reset();

    if g_usb_device_claim_interface(usb_dev, 0, 0, &mut error) == GFALSE {
        fpi_device_open_complete(device, error);
        return;
    }

    ensure_driver(device).start_probe();
    drive_rust(device, None);
}

unsafe fn cancel_internal(device: *mut FpDevice, recreate_cancellable: bool) {
    let self_dev = as_egismoc(device);
    self_dev.wait_finger_start = 0;

    if !self_dev.driver.is_null() {
        (*self_dev.driver).cancel();
    }

    if !self_dev.interrupt_cancellable.is_null() {
        g_cancellable_cancel(self_dev.interrupt_cancellable);
        clear_cancellable(&mut self_dev.interrupt_cancellable);
    }

    if recreate_cancellable {
        self_dev.interrupt_cancellable = g_cancellable_new();
    }
}

unsafe extern "C" fn egismoc_cancel(device: *mut FpDevice) {
    cancel_internal(device, true);
}

unsafe extern "C" fn egismoc_suspend(device: *mut FpDevice) {
    // La suspensión del sistema corta alimentación USB al lector: invalidamos el claim SDCP
    // y notificamos FP_DEVICE_ERROR_NOT_SUPPORTED conforme al contrato de fpi_device_suspend_complete,
    // de modo que libfprint cancele y espere ordenadamente cualquier operación en curso antes de dormir.
    if !as_egismoc(device).driver.is_null() {
        (*as_egismoc(device).driver).invalidate_sdcp_on_hardware_reset();
    }
    fpi_device_suspend_complete(device, fpi_device_error_new(FP_DEVICE_ERROR_NOT_SUPPORTED));
}

unsafe extern "C" fn egismoc_resume(device: *mut FpDevice) {
    if !as_egismoc(device).driver.is_null() {
        (*as_egismoc(device).driver).invalidate_sdcp_on_hardware_reset();
    }
    fpi_device_resume_complete(device, ptr::null_mut());
}

unsafe extern "C" fn egismoc_close(device: *mut FpDevice) {
    let mut error: *mut GError = ptr::null_mut();

    cancel_internal(device, false);

    let usb_dev = fpi_device_get_usb_device(device);
    g_usb_device_release_interface(usb_dev, 0, 0, &mut error);
    fpi_device_close_complete(device, error);
}

unsafe extern "C" fn egismoc_list(device: *mut FpDevice) {
    ensure_driver(device).start_list();
    drive_rust(device, None);
}

unsafe extern "C" fn egismoc_identify_verify(device: *mut FpDevice) {
    ensure_driver(device).start_identify();
    drive_rust(device, None);
}

unsafe extern "C" fn egismoc_enroll(device: *mut FpDevice) {
    ensure_driver(device).start_enroll();
    drive_rust(device, None);
}

unsafe extern "C" fn egismoc_delete(device: *mut FpDevice) {
    let _ = ensure_driver(device);
    let mut delete_print: *mut FpPrint = ptr::null_mut();
    let mut print_data: *mut GVariant = ptr::null_mut();

    fpi_device_get_delete_data(device, &mut delete_print);
    if delete_print.is_null() {
        fpi_device_delete_complete(device, fpi_device_error_new(FP_DEVICE_ERROR_DATA_INVALID));
        return;
    }

    g_object_get(
        delete_print as gpointer,
        c"fpi-data".as_ptr(),
        &mut print_data,
        ptr::null_mut::<c_void>(),
    );

    if print_data.is_null()
        || g_variant_check_format_string(print_data, c"(@ay)".as_ptr(), GFALSE) == GFALSE
    {
        if !print_data.is_null() {
            g_variant_unref(print_data);
        }
        fpi_device_delete_complete(device, fpi_device_error_new(FP_DEVICE_ERROR_DATA_INVALID));
        return;
    }

    let id_var = g_variant_get_child_value(print_data, 0);
    let mut id_len: gsize = 0;
    let id_ptr = g_variant_get_fixed_array(id_var, &mut id_len, 1) as *const u8;

    if id_ptr.is_null() || id_len != SDCP_ENROLLMENT_ID_SIZE {
        g_variant_unref(id_var);
        g_variant_unref(print_data);
        fpi_device_delete_complete(device, fpi_device_error_new(FP_DEVICE_ERROR_DATA_INVALID));
        return;
    }

    let mut target_id = [0u8; SDCP_ENROLLMENT_ID_SIZE];
    target_id.copy_from_slice(slice::from_raw_parts(id_ptr, SDCP_ENROLLMENT_ID_SIZE));

    g_variant_unref(id_var);
    g_variant_unref(print_data);

    ensure_driver(device).start_delete(target_id);
    drive_rust(device, None);
}

unsafe extern "C" fn egismoc_clear_storage(device: *mut FpDevice) {
    ensure_driver(device).start_clear_storage();
    drive_rust(device, None);
}

unsafe extern "C" fn fpi_device_egismoc_finalize(object: *mut GObject) {
    let self_dev = &mut *(object as *mut FpiDeviceEgisMoc);
    clear_cancellable(&mut self_dev.interrupt_cancellable);

    if !self_dev.driver.is_null() {
        let drv = self_dev.driver;
        self_dev.driver = ptr::null_mut();
        drop(Box::from_raw(drv));
    }

    let parent_cls = PARENT_CLASS.load(Ordering::Acquire) as *const GObjectClass;
    if !parent_cls.is_null() {
        if let Some(finalize_fn) = (*parent_cls).finalize {
            finalize_fn(object);
        }
    }
}

unsafe extern "C" fn fpi_device_egismoc_init(instance: *mut GTypeInstance, _g_class: gpointer) {
    let self_dev = &mut *(instance as *mut FpiDeviceEgisMoc);
    self_dev.driver = ptr::null_mut();
    self_dev.wait_finger_start = 0;
    self_dev.interrupt_cancellable = ptr::null_mut();
}

unsafe extern "C" fn fpi_device_egismoc_class_init(g_class: gpointer, _class_data: gpointer) {
    let parent = g_type_class_peek_parent(g_class);
    PARENT_CLASS.store(parent, Ordering::Release);

    let object_class = &mut *(g_class as *mut GObjectClass);
    let dev_class = &mut *(g_class as *mut FpDeviceClass);

    object_class.finalize = Some(fpi_device_egismoc_finalize);

    dev_class.id = c"egismoc".as_ptr();
    dev_class.full_name = c"Egis Technology (LighTuning) Match-on-Chip".as_ptr();

    dev_class.device_type = FP_DEVICE_TYPE_USB;
    dev_class.scan_type = FP_SCAN_TYPE_PRESS;
    dev_class.id_table = EGISMOC_ID_TABLE.as_ptr();
    dev_class.nr_enroll_stages = EGISMOC_MAX_ENROLL_STAGES_DEFAULT;
    dev_class.temp_hot_seconds = 0;

    dev_class.probe = Some(egismoc_probe);
    dev_class.open = Some(egismoc_open);
    dev_class.cancel = Some(egismoc_cancel);
    dev_class.suspend = Some(egismoc_suspend);
    dev_class.resume = Some(egismoc_resume);
    dev_class.close = Some(egismoc_close);
    dev_class.identify = Some(egismoc_identify_verify);
    dev_class.verify = Some(egismoc_identify_verify);
    dev_class.enroll = Some(egismoc_enroll);
    dev_class.delete = Some(egismoc_delete);
    dev_class.clear_storage = Some(egismoc_clear_storage);
    dev_class.list = Some(egismoc_list);

    fpi_device_class_auto_initialize_features(dev_class);
    dev_class.features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_table_covers_all_models_and_terminates() {
        assert_eq!(EGISMOC_ID_TABLE.len(), 8);
        assert_eq!(EGISMOC_ID_TABLE[0].vid, 0x1c7a);
        assert_eq!(EGISMOC_ID_TABLE[0].pid, 0x0582);
        assert_eq!(EGISMOC_ID_TABLE[6].pid, 0x05a5);
        assert_eq!(EGISMOC_ID_TABLE[7].vid, 0);
        assert_eq!(EGISMOC_ID_TABLE[7].pid, 0);
        assert_eq!(EGISMOC_ID_TABLE[7].driver_data, 0);
    }
}
