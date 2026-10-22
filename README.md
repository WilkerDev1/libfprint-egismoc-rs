# `libfprint-egismoc-rs` — Driver Sans-I/O en Rust + Puente GObject en C para Egis Match-on-Chip (`1c7a:0582` SDCP)

Implementación experimental **Nivel 3** del driver para lectores de huellas **Egis Technology (LighTuning) Match-on-Chip** (`1c7a:0582` – `1c7a:05a5`) con soporte completo para **Microsoft SDCP (Secure Device Connection Protocol)**, compilado como librería estática de Rust (`libegismoc_core.a`) e integrado nativamente dentro de `libfprint-2.so.2.0.0`.

---

## 1. Arquitectura Sans-I/O

En el driver original en C (`egismoc.c`), la lógica de estados, el ensamblado de paquetes binarios, la gestión de memoria manual (`g_malloc0`/`g_free`/`g_steal_pointer`) y las transferencias asíncronas de `libgusb` están entrelazados en tres máquinas de estados finitos (`FpiSsm`: `task_ssm`, `cmd_ssm` y `wait_finger_ssm`). Esa arquitectura propició bugs sutiles en producción:
- **`assertion failed: (self->task_ssm == NULL)`**: abortos de `fprintd` (`SIGABRT`) cuando una operación (`open`, `identify`, `enroll`) se cancelaba mientras esperaba una interrupción de dedo y quedaba un puntero `task_ssm` colgado.
- **Reinicio de sesión volátil SDCP tras reset USB**: al ejecutar `g_usb_device_reset()` en `egismoc_open()`, el sensor `1c7a:0582` pierde la sesión SDCP en RAM mientras conserva las huellas en flash, causando que `fpi_sdcp_verify_authorized_identity()` rechace erróneamente un `enrollment_id` válido identificado por el hardware.

En esta arquitectura **Sans-I/O**, toda la lógica del protocolo, criptografía y máquinas de estado vive en Rust puro (`egismoc-core`) sin realizar llamadas de entrada/salida ni depender de `FpiSsm`:

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         libfprint-2.so.2.0.0                              │
│                                                                           │
│  ┌─────────────────────────────────┐      ┌────────────────────────────┐  │
│  │   Puente GObject (c-bridge/)    │      │  egismoc-core (Rust .a)    │  │
│  │   egismoc.c (~475 líneas)       │      │                            │  │
│  │                                 │ step │  • state.rs (Sans-I/O)     │  │
│  │  • Registro de FpiDeviceEgisMoc ├─────►│    TaskState::Probe/List/  │  │
│  │  • Despacho FpiUsbTransfer      │      │    Identify/Enroll/Delete  │  │
│  │    (Control / Bulk / Interrupt) │◄─────┤  • protocol.rs             │  │
│  │  • Reporte a libfprint          │Action│    Tramas EGIS + Checksum  │  │
│  │    (progreso, match, errores)   │      │  • sdcp.rs                 │  │
│  └─────────────────────────────────┘      │    ECDH P-256 + KBKDF      │  │
│                                           └────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

### Ventajas de Diseño
1. **Cancelación limpia por construcción**: `EgisMocDriver::cancel(&mut self)` simplemente ejecuta `self.task = None`. No existen punteros `FpiSsm *` anidados que puedan desincronizarse ni provocar `SIGABRT`.
2. **Tolerancia explícita a reinicios USB (`MacMismatchAfterReset`)**: `SdcpSession::verify_authorized_identity()` devuelve un enum tipado (`IdentityVerification::{Verified, MacMismatchAfterReset, NotConnected}`), permitiendo conservar la coincidencia en hardware del `enrollment_id` de 32 bytes cuando el bus USB reinicia la sesión volátil.
3. **Verificación determinista sin hardware**: Al ser una máquina de estados pura conducida por `step(&mut self, rx: Option<&[u8]>) -> Action`, todos los flujos (`Probe`, `List`, `Identify`, `Enroll`, `Delete`, `ClearStorage`) se prueban en milisegundos con `cargo test`.

---

## 2. Estructura del Proyecto

| Ruta | Descripción |
| :--- | :--- |
| `egismoc-core/src/sdcp.rs` | Implementación en Rust de Microsoft SDCP: ECDH P-256, SP800-108 Counter Mode KBKDF HMAC-SHA256, parseo ASN.1 DER seguro y tolerancia `MacMismatchAfterReset`. |
| `egismoc-core/src/protocol.rs` | Constantes de `egismoc.h`, empaquetado con prefijo `EGIS`, checksum en complemento a uno de 16 bits (`egismoc_write_check_bytes`) y parseo de respuestas. |
| `egismoc-core/src/state.rs` | Máquina de estados Sans-I/O (`Probe`, `List`, `Identify`, `Enroll`, `Delete`, `ClearStorage`) con soporte para variantes `ModelType1` (`0582`/`0583`) y `ModelType2` (`0584`–`0587`, `05a1`, `05a5`). |
| `egismoc-core/src/ffi.rs` | Interfaz C ABI (`extern "C"`) exportada como `libegismoc_core.a`. |
| `egismoc-core/include/egismoc_rs.h` | Cabecera C con los tipos `EgisMocRs`, `EgisMocAction` y funciones FFI. |
| `c-bridge/egismoc.c` | Puente GObject minimalista para `libfprint` sin `FpiSsm`. |
| `PKGBUILD` | Script de empaquetado de Arch Linux (`libfprint-egismoc-rs-git`). |
| `install-rust-driver.sh` | Instala el paquete `.pkg.tar.zst` compilado con Rust y reinicia `fprintd`. |
| `restore-c-driver.sh` | Revierte inmediatamente al paquete C SDCP anterior y reinicia `fprintd`. |

---

## 3. Comparativa Real de Líneas de Código (C vs. Rust + Puente C)

| Componente | Versión C Original (`libfprint-egismoc-sdcp`) | Versión Híbrida Rust + Puente C (`libfprint-egismoc-rs`) |
| :--- | ---: | ---: |
| **Driver GObject en C (`egismoc.c` + `egismoc.h`)** | 2,234 líneas (`1,986` + `248`) | **512 líneas** (`477` + `35` en `c-bridge/`) |
| **Subsistema SDCP en C (`fpi-sdcp-device.c/.h`)** | 1,672 líneas (`1,466` + `156` + `50`) | Reemplazado en el driver por `src/sdcp.rs` |
| **Núcleo Rust (`sdcp.rs` + `protocol.rs` + `state.rs` + `ffi.rs`)** | — | **1,468 líneas** de código + **548 líneas** de tests unitarios integrados |
| **Cabecera FFI (`include/egismoc_rs.h`)** | — | **124 líneas** |
| **Código C inseguro en el driver (`FpiSsm`, buffers manuales)** | **3,906 líneas** | **512 líneas** (**reducción del 86.9% de código C**) |

---

## 4. Resultados de las Pruebas

### 4.1 Suite Unitaria en Rust (`cargo test`)
Ejecutada en `egismoc-core/`:
- **12 / 12 tests aprobados (`0.01s`)**:
  - `sdcp::tests::test_host_keys_and_random_vectors`
  - `sdcp::tests::test_derive_keys_and_verify_connect_vectors`
  - `sdcp::tests::test_verify_connect_from_standard_buf_and_egismoc_frame`
  - `sdcp::tests::test_verify_reconnect_and_authorized_identity_and_enrollment_id`
  - `sdcp::tests::test_get_cert_length_from_buf_with_extra_bytes`
  - `protocol::tests::test_cmd_fw_version_and_cmd_list_wrapping_and_checksums`
  - `protocol::tests::test_delete_cmd_and_new_print_cmd_and_check_cmd_byte_exact`
  - `protocol::tests::test_parse_list_and_identify_responses`
  - `state::tests::test_probe_flow_and_model_variants`
  - `state::tests::test_list_and_delete_flows`
  - `state::tests::test_identify_with_usb_reset_mac_mismatch_and_cancellation`
  - `state::tests::test_enroll_full_state_machine`

### 4.2 Suite de Integración de `libfprint` + `umockdev` (`meson test`)
Ejecutada contra `libfprint-2.so.2.0.0` enlazado con `libegismoc_core.a`, incluyendo la reproducción completa de captura USB real (`tests/egismoc/custom.pcapng` + `tests/egismoc/custom.py`):
- `drivers - libfprint:egismoc`: **OK (`0.45s`)** — valida `open`, `fw_version`, `list`, `clear_storage`, `enroll` (10 etapas), `verify`, `identify` asíncrono, detección de huella duplicada (`FP_DEVICE_ERROR_DATA_DUPLICATE`), `enroll` de segunda huella, `delete` individual y `close`.
- `unit-tests - libfprint:fpi-sdcp-device`: **OK (`3.03s`)**
- `unit-tests - libfprint:fpi-device`: **OK (`7.51s`)**
- `unit-tests - libfprint:fpi-ssm`: **OK (`1.05s`)**
- `unit-tests - libfprint:fpi-assembling`: **OK (`0.68s`)**
- `data+no-valgrind - libfprint:metainfo-validate`: **OK (`0.02s`)**

---

## 5. Instalación y Reversión en Arch Linux

El paquete instalable compilado se encuentra listo en este directorio (`libfprint-egismoc-rs-git-r1831.4d128d4-1-x86_64.pkg.tar.zst`).

### Instalar el driver en Rust
```bash
./install-rust-driver.sh
```

### Volver al driver en C (Rollback inmediato)
```bash
./restore-c-driver.sh
```
