//! `egismoc-core` — Driver 100% en Rust (`staticlib` + `rlib`) para lectores de huellas
//! Egis Technology Match-on-Chip (`1c7a:0582` – `1c7a:05a5`) con Microsoft SDCP y adaptador
//! GObject/USB nativo para `libfprint` (cero código C en el controlador).
//!
//! Los tres módulos de lógica crítica (`protocol`, `sdcp`, `state`) aplican `#![forbid(unsafe_code)]`.
//! El código `unsafe` queda confinado exclusivamente a la frontera FFI con GLib/GObject/libfprint
//! (`glib_ffi` y `gobject_usb`), con verificación de ABI en tiempo de compilación.

pub mod glib_ffi;
pub mod gobject_usb;
pub mod protocol;
pub mod sdcp;
pub mod state;

/// Devuelve `true` cuando `libfprint` ejecuta pruebas de emulación `umockdev`
/// (`FP_DEVICE_EMULATION=1`).
#[inline]
pub fn is_emulation_mode() -> bool {
    std::env::var_os("FP_DEVICE_EMULATION").as_deref() == Some(std::ffi::OsStr::new("1"))
}
