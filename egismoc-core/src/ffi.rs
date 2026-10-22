//! Interfaz C ABI (`extern "C"`) para consumir la máquina de estados Sans-I/O
//! `EgisMocDriver` desde el puente GObject de `libfprint` (`c-bridge/egismoc.c`).

#![allow(clippy::missing_safety_doc)]

use crate::protocol::CaptureReadStatus;
use crate::sdcp::{IdentityVerification, SDCP_ENROLLMENT_ID_SIZE};
use crate::state::{Action, DriverError, EgisMocDriver, TaskResult};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgisMocActionKind {
    Idle = 0,
    ControlTransfer = 1,
    SendCommand = 2,
    WaitFingerOnSensor = 3,
    TaskComplete = 4,
    Error = 5,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgisMocCaptureStatus {
    Success = 0,
    OffCenter = 1,
    DirtySensor = 2,
    RetryUnknown = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgisMocResultKind {
    None = 0,
    ProbeComplete = 1,
    ListComplete = 2,
    IdentifyComplete = 3,
    EnrollComplete = 4,
    DeleteComplete = 5,
    ClearStorageComplete = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgisMocIdentityVerification {
    Verified = 0,
    MacMismatchAfterReset = 1,
    NotConnected = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgisMocErrorKind {
    None = 0,
    General = 1,
    Proto = 2,
    DataInvalid = 3,
    DataNotFound = 4,
    DataFull = 5,
    DataDuplicate = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EgisMocAction {
    pub kind: EgisMocActionKind,

    // Campos para ControlTransfer
    pub ctrl_direction: u8,
    pub ctrl_request_type: u8,
    pub ctrl_recipient: u8,
    pub ctrl_request: u8,
    pub ctrl_value: u16,
    pub ctrl_index: u16,
    pub ctrl_length: usize,

    // Campos para SendCommand
    pub tx_ptr: *const u8,
    pub tx_len: usize,
    pub report_finger_present: bool,

    // Progreso parcial de Enroll
    pub has_enroll_progress: bool,
    pub enroll_stage: i32,
    pub enroll_capture_status: EgisMocCaptureStatus,

    // Resultado de TaskComplete
    pub result_kind: EgisMocResultKind,
    pub has_matched_id: bool,
    pub enrollment_id: [u8; SDCP_ENROLLMENT_ID_SIZE],
    pub identity_verification: EgisMocIdentityVerification,
    pub enrolled_ids_count: usize,

    // Resultado de Error
    pub error_kind: EgisMocErrorKind,
}

impl Default for EgisMocAction {
    fn default() -> Self {
        Self {
            kind: EgisMocActionKind::Idle,
            ctrl_direction: 0,
            ctrl_request_type: 0,
            ctrl_recipient: 0,
            ctrl_request: 0,
            ctrl_value: 0,
            ctrl_index: 0,
            ctrl_length: 0,
            tx_ptr: ptr::null(),
            tx_len: 0,
            report_finger_present: false,
            has_enroll_progress: false,
            enroll_stage: 0,
            enroll_capture_status: EgisMocCaptureStatus::Success,
            result_kind: EgisMocResultKind::None,
            has_matched_id: false,
            enrollment_id: [0u8; SDCP_ENROLLMENT_ID_SIZE],
            identity_verification: EgisMocIdentityVerification::Verified,
            enrolled_ids_count: 0,
            error_kind: EgisMocErrorKind::None,
        }
    }
}

/// Contexto opaco exportado al puente C (`EgisMocRs *`).
pub struct EgisMocRs {
    pub driver: EgisMocDriver,
    pub last_tx: Vec<u8>,
}

#[no_mangle]
pub extern "C" fn egismoc_rs_new(driver_data: u64) -> *mut EgisMocRs {
    let ctx = Box::new(EgisMocRs {
        driver: EgisMocDriver::from_driver_data(driver_data),
        last_tx: Vec::new(),
    });
    Box::into_raw(ctx)
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_free(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_set_device_id(
    ctx: *mut EgisMocRs,
    driver_name: *const c_char,
    device_id: *const c_char,
) {
    if ctx.is_null() || driver_name.is_null() || device_id.is_null() {
        return;
    }
    let ctx = &mut *ctx;
    let Ok(drv_str) = CStr::from_ptr(driver_name).to_str() else {
        return;
    };
    let Ok(dev_str) = CStr::from_ptr(device_id).to_str() else {
        return;
    };
    let path = crate::sdcp::SdcpSession::default_claim_cache_path(drv_str, dev_str);
    ctx.driver.sdcp.set_claim_cache_path(path);
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_max_enroll_stages(ctx: *const EgisMocRs) -> i32 {
    if ctx.is_null() {
        return 10;
    }
    (*ctx).driver.max_enroll_stages
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_cancel(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        (*ctx).driver.cancel();
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_start_probe(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        (*ctx).driver.start_probe();
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_start_list(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        (*ctx).driver.start_list();
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_start_identify(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        (*ctx).driver.start_identify();
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_start_enroll(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        (*ctx).driver.start_enroll();
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_start_delete(
    ctx: *mut EgisMocRs,
    target_id: *const u8,
) {
    if ctx.is_null() || target_id.is_null() {
        return;
    }
    let slice = slice::from_raw_parts(target_id, SDCP_ENROLLMENT_ID_SIZE);
    let mut id = [0u8; SDCP_ENROLLMENT_ID_SIZE];
    id.copy_from_slice(slice);
    (*ctx).driver.start_delete(id);
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_start_clear_storage(ctx: *mut EgisMocRs) {
    if !ctx.is_null() {
        (*ctx).driver.start_clear_storage();
    }
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_get_enrolled_id(
    ctx: *const EgisMocRs,
    index: usize,
    out_id: *mut u8,
) -> bool {
    if ctx.is_null() || out_id.is_null() {
        return false;
    }
    let ctx = &*ctx;
    let Some(id) = ctx.driver.enrolled_ids.get(index) else {
        return false;
    };
    ptr::copy_nonoverlapping(id.as_ptr(), out_id, SDCP_ENROLLMENT_ID_SIZE);
    true
}

#[no_mangle]
pub unsafe extern "C" fn egismoc_rs_step(
    ctx: *mut EgisMocRs,
    rx_ptr: *const u8,
    rx_len: usize,
    out_action: *mut EgisMocAction,
) {
    if ctx.is_null() || out_action.is_null() {
        return;
    }
    let ctx = &mut *ctx;
    let rx_opt = if rx_ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(rx_ptr, rx_len))
    };

    let mut c_act = EgisMocAction::default();
    match ctx.driver.step(rx_opt) {
        Action::Idle => {
            c_act.kind = EgisMocActionKind::Idle;
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
            c_act.kind = EgisMocActionKind::ControlTransfer;
            c_act.ctrl_direction = direction as u8;
            c_act.ctrl_request_type = request_type as u8;
            c_act.ctrl_recipient = recipient as u8;
            c_act.ctrl_request = request;
            c_act.ctrl_value = value;
            c_act.ctrl_index = index;
            c_act.ctrl_length = length;
        }
        Action::SendCommand {
            packet,
            finger_present,
            enroll_progress,
        } => {
            ctx.last_tx = packet;
            c_act.kind = EgisMocActionKind::SendCommand;
            c_act.tx_ptr = ctx.last_tx.as_ptr();
            c_act.tx_len = ctx.last_tx.len();
            c_act.report_finger_present = finger_present;
            if let Some(prog) = enroll_progress {
                c_act.has_enroll_progress = true;
                c_act.enroll_stage = prog.completed_stages;
                c_act.enroll_capture_status = match prog.status {
                    CaptureReadStatus::Success => EgisMocCaptureStatus::Success,
                    CaptureReadStatus::OffCenter => EgisMocCaptureStatus::OffCenter,
                    CaptureReadStatus::DirtySensor => EgisMocCaptureStatus::DirtySensor,
                    CaptureReadStatus::RetryUnknown => EgisMocCaptureStatus::RetryUnknown,
                };
            }
        }
        Action::WaitFingerOnSensor { enroll_progress } => {
            c_act.kind = EgisMocActionKind::WaitFingerOnSensor;
            if let Some(prog) = enroll_progress {
                c_act.has_enroll_progress = true;
                c_act.enroll_stage = prog.completed_stages;
            }
        }
        Action::TaskComplete(res) => {
            c_act.kind = EgisMocActionKind::TaskComplete;
            match res {
                TaskResult::ProbeComplete { .. } => {
                    c_act.result_kind = EgisMocResultKind::ProbeComplete;
                }
                TaskResult::ListComplete { enrolled_ids } => {
                    c_act.result_kind = EgisMocResultKind::ListComplete;
                    c_act.enrolled_ids_count = enrolled_ids.len();
                }
                TaskResult::IdentifyComplete {
                    matched_enrollment_id,
                    verification,
                } => {
                    c_act.result_kind = EgisMocResultKind::IdentifyComplete;
                    if let Some(id) = matched_enrollment_id {
                        c_act.has_matched_id = true;
                        c_act.enrollment_id = id;
                    }
                    c_act.identity_verification = match verification {
                        Some(IdentityVerification::Verified) => {
                            EgisMocIdentityVerification::Verified
                        }
                        Some(IdentityVerification::MacMismatchAfterReset) => {
                            EgisMocIdentityVerification::MacMismatchAfterReset
                        }
                        _ => EgisMocIdentityVerification::NotConnected,
                    };
                }
                TaskResult::EnrollComplete { enrollment_id } => {
                    c_act.result_kind = EgisMocResultKind::EnrollComplete;
                    c_act.has_matched_id = true;
                    c_act.enrollment_id = enrollment_id;
                }
                TaskResult::DeleteComplete => {
                    c_act.result_kind = EgisMocResultKind::DeleteComplete;
                }
                TaskResult::ClearStorageComplete => {
                    c_act.result_kind = EgisMocResultKind::ClearStorageComplete;
                }
            }
        }
        Action::Error(err) => {
            c_act.kind = EgisMocActionKind::Error;
            c_act.error_kind = match err {
                DriverError::General(_) => EgisMocErrorKind::General,
                DriverError::Proto(_) => EgisMocErrorKind::Proto,
                DriverError::DataInvalid(_) => EgisMocErrorKind::DataInvalid,
                DriverError::DataNotFound(_) => EgisMocErrorKind::DataNotFound,
                DriverError::DataFull => EgisMocErrorKind::DataFull,
                DriverError::DataDuplicate => EgisMocErrorKind::DataDuplicate,
            };
        }
    }

    *out_action = c_act;
}
