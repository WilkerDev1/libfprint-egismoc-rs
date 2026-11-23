//! Bindings FFI de ABI exacto (`#[repr(C)]`) para GLib, GObject, GIO, GUsb y la API interna
//! de `libfprint` (`fpi_*`).
//!
//! Todos los tamaños y offsets de estructuras críticas (`FpDeviceClass`, `FpIdEntry`,
//! `FpiUsbTransfer`, `GObjectClass`, `GPtrArray`) se verifican en tiempo de compilación
//! mediante `const` assertions contra el ABI real de `libfprint` en Linux x86_64/64-bit.

#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::{offset_of, size_of};

pub type GType = usize;
pub type gboolean = c_int;
pub type gint = c_int;
pub type guint = c_uint;
pub type guint8 = u8;
pub type guint16 = u16;
pub type gint32 = i32;
pub type guint32 = u32;
pub type gint64 = i64;
pub type guint64 = u64;
pub type gsize = usize;
pub type gssize = isize;
pub type gpointer = *mut c_void;
pub type gconstpointer = *const c_void;
pub type GQuark = u32;

pub const GFALSE: gboolean = 0;
pub const GTRUE: gboolean = 1;

// Tipos opacos de GLib / GIO / GUsb / libfprint
#[repr(C)]
pub struct GError {
    pub domain: GQuark,
    pub code: gint,
    pub message: *mut c_char,
}

#[repr(C)]
pub struct GCancellable {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GUsbDevice {
    _private: [u8; 0],
}

#[repr(C)]
pub struct FpPrint {
    _private: [u8; 0],
}

#[repr(C)]
pub struct FpiSsm {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GVariant {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GVariantType {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GPtrArray {
    pub pdata: *mut gpointer,
    pub len: guint,
}

#[repr(C)]
pub struct GTypeInstance {
    pub g_class: *mut c_void,
}

#[repr(C)]
pub struct GObject {
    pub g_type_instance: GTypeInstance,
    pub ref_count: guint,
    pub qdata: *mut c_void,
}

#[repr(C)]
pub struct FpDevice {
    pub parent_instance: GObject,
}

#[repr(C)]
pub struct GTypeClass {
    pub g_type: GType,
}

/// Representación ABI exacta de `GObjectClass` (136 bytes en 64-bit, `finalize` en offset 48).
#[repr(C)]
pub struct GObjectClass {
    pub g_type_class: GTypeClass,
    pub construct_properties: *mut c_void,
    pub constructor: Option<unsafe extern "C" fn(GType, guint, *mut c_void) -> *mut GObject>,
    pub set_property: *mut c_void,
    pub get_property: *mut c_void,
    pub dispose: Option<unsafe extern "C" fn(*mut GObject)>,
    pub finalize: Option<unsafe extern "C" fn(*mut GObject)>,
    pub dispatch_properties_changed: *mut c_void,
    pub notify: *mut c_void,
    pub constructed: Option<unsafe extern "C" fn(*mut GObject)>,
    pub flags: gsize,
    pub n_construct_properties: gsize,
    pub pspecs: gpointer,
    pub n_pspecs: gsize,
    pub pdummy: [gpointer; 3],
}

/// Entrada en la tabla de dispositivos soportados (`FpIdEntry`, 32 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FpIdEntry {
    pub pid: guint,
    pub vid: guint,
    pub _union_pad: [u64; 2],
    pub driver_data: guint64,
}

impl FpIdEntry {
    pub const fn usb(vid: guint, pid: guint, driver_data: guint64) -> Self {
        Self {
            pid,
            vid,
            _union_pad: [0, 0],
            driver_data,
        }
    }

    pub const fn terminator() -> Self {
        Self {
            pid: 0,
            vid: 0,
            _union_pad: [0, 0],
            driver_data: 0,
        }
    }
}

// Constantes enum verificadas contra libfprint / GLib / GUsb
pub const FP_DEVICE_TYPE_USB: c_int = 2;
pub const FP_SCAN_TYPE_PRESS: c_int = 1;
pub const FP_DEVICE_FEATURE_DUPLICATES_CHECK: guint = 128;

pub const FP_FINGER_STATUS_NONE: guint = 0;
pub const FP_FINGER_STATUS_NEEDED: guint = 1;
pub const FP_FINGER_STATUS_PRESENT: guint = 2;

pub const FPI_PRINT_RAW: c_int = 1;

pub const FPI_MATCH_ERROR: c_int = -1;
pub const FPI_MATCH_FAIL: c_int = 0;
pub const FPI_MATCH_SUCCESS: c_int = 1;

pub const FPI_DEVICE_ACTION_NONE: c_int = 0;
pub const FPI_DEVICE_ACTION_PROBE: c_int = 1;
pub const FPI_DEVICE_ACTION_OPEN: c_int = 2;
pub const FPI_DEVICE_ACTION_CLOSE: c_int = 3;
pub const FPI_DEVICE_ACTION_ENROLL: c_int = 4;
pub const FPI_DEVICE_ACTION_VERIFY: c_int = 5;
pub const FPI_DEVICE_ACTION_IDENTIFY: c_int = 6;
pub const FPI_DEVICE_ACTION_LIST: c_int = 8;
pub const FPI_DEVICE_ACTION_DELETE: c_int = 9;
pub const FPI_DEVICE_ACTION_CLEAR_STORAGE: c_int = 10;

pub const FP_DEVICE_ERROR_GENERAL: c_int = 0;
pub const FP_DEVICE_ERROR_NOT_SUPPORTED: c_int = 1;
pub const FP_DEVICE_ERROR_PROTO: c_int = 5;
pub const FP_DEVICE_ERROR_DATA_INVALID: c_int = 6;
pub const FP_DEVICE_ERROR_DATA_NOT_FOUND: c_int = 7;
pub const FP_DEVICE_ERROR_DATA_FULL: c_int = 8;
pub const FP_DEVICE_ERROR_DATA_DUPLICATE: c_int = 9;

pub const FP_DEVICE_RETRY_GENERAL: c_int = 0;
pub const FP_DEVICE_RETRY_CENTER_FINGER: c_int = 2;
pub const FP_DEVICE_RETRY_REMOVE_FINGER: c_int = 3;

pub const G_IO_ERROR_CANCELLED: c_int = 19;
pub const G_LOG_LEVEL_DEBUG: c_int = 128;
pub const G_LOG_LEVEL_INFO: c_int = 64;
pub const G_LOG_LEVEL_WARNING: c_int = 16;

pub const FPI_USB_ENDPOINT_OUT: guint8 = 0x00;
pub const FPI_USB_ENDPOINT_IN: guint8 = 0x80;

/// Representación ABI exacta de `FpDeviceClass` (304 bytes en 64-bit).
#[repr(C)]
pub struct FpDeviceClass {
    pub parent_class: GObjectClass,

    pub id: *const c_char,
    pub full_name: *const c_char,
    pub device_type: c_int,
    pub id_table: *const FpIdEntry,
    pub features: guint,

    pub nr_enroll_stages: gint,
    pub scan_type: c_int,

    pub temp_hot_seconds: gint32,
    pub temp_cold_seconds: gint32,

    pub usb_discover: Option<unsafe extern "C" fn(*mut GUsbDevice) -> gint>,
    pub probe: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub open: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub close: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub enroll: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub verify: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub identify: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub capture: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub list: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub delete: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub clear_storage: Option<unsafe extern "C" fn(*mut FpDevice)>,

    pub cancel: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub suspend: Option<unsafe extern "C" fn(*mut FpDevice)>,
    pub resume: Option<unsafe extern "C" fn(*mut FpDevice)>,
}

pub type GDestroyNotify = Option<unsafe extern "C" fn(gpointer)>;
pub type GEqualFunc = Option<unsafe extern "C" fn(gconstpointer, gconstpointer) -> gboolean>;
pub type GClassInitFunc = Option<unsafe extern "C" fn(gpointer, gpointer)>;
pub type GInstanceInitFunc = Option<unsafe extern "C" fn(*mut GTypeInstance, gpointer)>;

pub type FpiUsbTransferCallback = Option<
    unsafe extern "C" fn(
        transfer: *mut FpiUsbTransfer,
        dev: *mut FpDevice,
        user_data: gpointer,
        error: *mut GError,
    ),
>;

/// Representación ABI exacta de `FpiUsbTransfer` (104 bytes en 64-bit).
#[repr(C)]
pub struct FpiUsbTransfer {
    pub device: *mut FpDevice,
    pub ssm: *mut FpiSsm,
    pub length: gssize,
    pub actual_length: gssize,
    pub buffer: *mut guint8,

    pub ref_count: guint,
    pub transfer_type: c_int,
    pub endpoint: guint8,

    pub direction: c_int,
    pub request_type: c_int,
    pub recipient: c_int,
    pub request: guint8,
    pub value: guint16,
    pub idx: guint16,

    pub short_is_error: gboolean,

    pub user_data: gpointer,
    pub callback: FpiUsbTransferCallback,
    pub free_buffer: GDestroyNotify,
}

// Verificación estricta de ABI en tiempo de compilación (Linux 64-bit)
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<GType>() == 8);
    assert!(size_of::<GObject>() == 24);
    assert!(size_of::<GObjectClass>() == 136);
    assert!(offset_of!(GObjectClass, finalize) == 48);

    assert!(size_of::<FpDevice>() == 24);
    assert!(size_of::<FpDeviceClass>() == 304);
    assert!(offset_of!(FpDeviceClass, parent_class) == 0);
    assert!(offset_of!(FpDeviceClass, id) == 136);
    assert!(offset_of!(FpDeviceClass, full_name) == 144);
    assert!(offset_of!(FpDeviceClass, device_type) == 152);
    assert!(offset_of!(FpDeviceClass, id_table) == 160);
    assert!(offset_of!(FpDeviceClass, features) == 168);
    assert!(offset_of!(FpDeviceClass, nr_enroll_stages) == 172);
    assert!(offset_of!(FpDeviceClass, scan_type) == 176);
    assert!(offset_of!(FpDeviceClass, temp_hot_seconds) == 180);
    assert!(offset_of!(FpDeviceClass, temp_cold_seconds) == 184);
    assert!(offset_of!(FpDeviceClass, usb_discover) == 192);
    assert!(offset_of!(FpDeviceClass, probe) == 200);
    assert!(offset_of!(FpDeviceClass, open) == 208);
    assert!(offset_of!(FpDeviceClass, close) == 216);
    assert!(offset_of!(FpDeviceClass, enroll) == 224);
    assert!(offset_of!(FpDeviceClass, verify) == 232);
    assert!(offset_of!(FpDeviceClass, identify) == 240);
    assert!(offset_of!(FpDeviceClass, capture) == 248);
    assert!(offset_of!(FpDeviceClass, list) == 256);
    assert!(offset_of!(FpDeviceClass, delete) == 264);
    assert!(offset_of!(FpDeviceClass, clear_storage) == 272);
    assert!(offset_of!(FpDeviceClass, cancel) == 280);
    assert!(offset_of!(FpDeviceClass, suspend) == 288);
    assert!(offset_of!(FpDeviceClass, resume) == 296);

    assert!(size_of::<FpIdEntry>() == 32);
    assert!(offset_of!(FpIdEntry, pid) == 0);
    assert!(offset_of!(FpIdEntry, vid) == 4);
    assert!(offset_of!(FpIdEntry, driver_data) == 24);

    assert!(size_of::<FpiUsbTransfer>() == 104);
    assert!(offset_of!(FpiUsbTransfer, device) == 0);
    assert!(offset_of!(FpiUsbTransfer, ssm) == 8);
    assert!(offset_of!(FpiUsbTransfer, length) == 16);
    assert!(offset_of!(FpiUsbTransfer, actual_length) == 24);
    assert!(offset_of!(FpiUsbTransfer, buffer) == 32);
    assert!(offset_of!(FpiUsbTransfer, short_is_error) == 72);

    assert!(size_of::<GPtrArray>() == 16);
    assert!(offset_of!(GPtrArray, pdata) == 0);
    assert!(offset_of!(GPtrArray, len) == 8);
};

extern "C" {
    // GLib
    pub fn g_free(mem: gpointer);
    pub fn g_memdup2(mem: gconstpointer, byte_size: gsize) -> gpointer;
    pub fn g_strdup(str: *const c_char) -> *mut c_char;
    pub fn g_get_monotonic_time() -> gint64;
    pub fn g_intern_static_string(string: *const c_char) -> *const c_char;
    pub fn g_error_new_literal(domain: GQuark, code: gint, message: *const c_char) -> *mut GError;
    pub fn g_error_free(error: *mut GError);
    pub fn g_log(log_domain: *const c_char, log_level: c_int, format: *const c_char, ...);

    // GPtrArray
    pub fn g_ptr_array_new_with_free_func(element_free_func: GDestroyNotify) -> *mut GPtrArray;
    pub fn g_ptr_array_add(array: *mut GPtrArray, data: gpointer);
    pub fn g_ptr_array_find_with_equal_func(
        haystack: *mut GPtrArray,
        needle: gconstpointer,
        equal_func: GEqualFunc,
        index: *mut guint,
    ) -> gboolean;

    // GVariant
    pub fn g_variant_new_fixed_array(
        element_type: *const GVariantType,
        elements: gconstpointer,
        n_elements: gsize,
        element_size: gsize,
    ) -> *mut GVariant;
    pub fn g_variant_new_tuple(children: *const *mut GVariant, n_children: gsize) -> *mut GVariant;
    pub fn g_variant_check_format_string(
        value: *mut GVariant,
        format_string: *const c_char,
        copy_only: gboolean,
    ) -> gboolean;
    pub fn g_variant_get_child_value(value: *mut GVariant, index: gsize) -> *mut GVariant;
    pub fn g_variant_get_fixed_array(
        value: *mut GVariant,
        n_elements: *mut gsize,
        element_size: gsize,
    ) -> gconstpointer;
    pub fn g_variant_unref(value: *mut GVariant);

    // GObject
    pub fn g_type_register_static_simple(
        parent_type: GType,
        type_name: *const c_char,
        class_size: guint,
        class_init: GClassInitFunc,
        instance_size: guint,
        instance_init: GInstanceInitFunc,
        flags: c_int,
    ) -> GType;
    pub fn g_type_class_peek_parent(g_class: gpointer) -> gpointer;
    pub fn g_object_ref(object: gpointer) -> gpointer;
    pub fn g_object_ref_sink(object: gpointer) -> gpointer;
    pub fn g_object_unref(object: gpointer);
    pub fn g_object_set(object: gpointer, first_property_name: *const c_char, ...);
    pub fn g_object_get(object: gpointer, first_property_name: *const c_char, ...);

    // GIO
    pub fn g_cancellable_new() -> *mut GCancellable;
    pub fn g_cancellable_cancel(cancellable: *mut GCancellable);
    pub fn g_io_error_quark() -> GQuark;

    // GUsb
    pub fn g_usb_device_open(self_: *mut GUsbDevice, error: *mut *mut GError) -> gboolean;
    pub fn g_usb_device_close(self_: *mut GUsbDevice, error: *mut *mut GError) -> gboolean;
    pub fn g_usb_device_reset(self_: *mut GUsbDevice, error: *mut *mut GError) -> gboolean;
    pub fn g_usb_device_claim_interface(
        self_: *mut GUsbDevice,
        iface: gint,
        flags: c_int,
        error: *mut *mut GError,
    ) -> gboolean;
    pub fn g_usb_device_release_interface(
        self_: *mut GUsbDevice,
        iface: gint,
        flags: c_int,
        error: *mut *mut GError,
    ) -> gboolean;
    pub fn g_usb_device_get_serial_number_index(self_: *mut GUsbDevice) -> guint8;
    pub fn g_usb_device_get_string_descriptor(
        self_: *mut GUsbDevice,
        desc_index: guint8,
        error: *mut *mut GError,
    ) -> *mut c_char;

    // libfprint public
    pub fn fp_device_get_type() -> GType;
    pub fn fp_device_get_driver(device: *mut FpDevice) -> *const c_char;
    pub fn fp_device_get_device_id(device: *mut FpDevice) -> *const c_char;
    pub fn fp_print_new(device: *mut FpDevice) -> *mut FpPrint;
    pub fn fp_print_equal(self_: *mut FpPrint, other: *mut FpPrint) -> gboolean;

    // libfprint internal (fpi_*)
    pub fn fpi_device_class_auto_initialize_features(device_class: *mut FpDeviceClass);
    pub fn fpi_device_get_usb_device(device: *mut FpDevice) -> *mut GUsbDevice;
    pub fn fpi_device_get_driver_data(device: *mut FpDevice) -> guint64;
    pub fn fpi_device_get_current_action(device: *mut FpDevice) -> c_int;
    pub fn fpi_device_action_is_cancelled(device: *mut FpDevice) -> gboolean;
    pub fn fpi_device_get_cancellable(device: *mut FpDevice) -> *mut GCancellable;
    pub fn fpi_device_set_nr_enroll_stages(device: *mut FpDevice, enroll_stages: gint);

    pub fn fpi_device_get_enroll_data(device: *mut FpDevice, print: *mut *mut FpPrint);
    pub fn fpi_device_get_verify_data(device: *mut FpDevice, print: *mut *mut FpPrint);
    pub fn fpi_device_get_identify_data(device: *mut FpDevice, prints: *mut *mut GPtrArray);
    pub fn fpi_device_get_delete_data(device: *mut FpDevice, print: *mut *mut FpPrint);

    pub fn fpi_device_error_new(error: c_int) -> *mut GError;
    pub fn fpi_device_error_new_msg(error: c_int, msg: *const c_char, ...) -> *mut GError;
    pub fn fpi_device_retry_new(error: c_int) -> *mut GError;
    pub fn fpi_device_retry_new_msg(error: c_int, msg: *const c_char, ...) -> *mut GError;

    pub fn fpi_device_action_error(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_probe_complete(
        device: *mut FpDevice,
        device_id: *const c_char,
        device_name: *const c_char,
        error: *mut GError,
    );
    pub fn fpi_device_open_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_close_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_enroll_complete(
        device: *mut FpDevice,
        print: *mut FpPrint,
        error: *mut GError,
    );
    pub fn fpi_device_verify_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_identify_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_delete_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_list_complete(
        device: *mut FpDevice,
        prints: *mut GPtrArray,
        error: *mut GError,
    );
    pub fn fpi_device_clear_storage_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_suspend_complete(device: *mut FpDevice, error: *mut GError);
    pub fn fpi_device_resume_complete(device: *mut FpDevice, error: *mut GError);

    pub fn fpi_device_enroll_progress(
        device: *mut FpDevice,
        completed_stages: gint,
        print: *mut FpPrint,
        error: *mut GError,
    );
    pub fn fpi_device_verify_report(
        device: *mut FpDevice,
        result: c_int,
        print: *mut FpPrint,
        error: *mut GError,
    );
    pub fn fpi_device_identify_report(
        device: *mut FpDevice,
        match_: *mut FpPrint,
        print: *mut FpPrint,
        error: *mut GError,
    );
    pub fn fpi_device_report_finger_status(device: *mut FpDevice, finger_status: guint)
        -> gboolean;

    pub fn fpi_print_set_type(print: *mut FpPrint, print_type: c_int);
    pub fn fpi_print_set_device_stored(print: *mut FpPrint, device_stored: gboolean);

    pub fn fpi_usb_transfer_new(device: *mut FpDevice) -> *mut FpiUsbTransfer;
    pub fn fpi_usb_transfer_fill_bulk(
        transfer: *mut FpiUsbTransfer,
        endpoint: guint8,
        length: gsize,
    );
    pub fn fpi_usb_transfer_fill_bulk_full(
        transfer: *mut FpiUsbTransfer,
        endpoint: guint8,
        buffer: *mut guint8,
        length: gsize,
        free_func: GDestroyNotify,
    );
    pub fn fpi_usb_transfer_fill_control(
        transfer: *mut FpiUsbTransfer,
        direction: c_int,
        request_type: c_int,
        recipient: c_int,
        request: guint8,
        value: guint16,
        idx: guint16,
        length: gsize,
    );
    pub fn fpi_usb_transfer_fill_interrupt(
        transfer: *mut FpiUsbTransfer,
        endpoint: guint8,
        length: gsize,
    );
    pub fn fpi_usb_transfer_submit(
        transfer: *mut FpiUsbTransfer,
        timeout_ms: guint,
        cancellable: *mut GCancellable,
        callback: FpiUsbTransferCallback,
        user_data: gpointer,
    );
}
