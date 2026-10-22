# `libfprint-egismoc-rs`

[![CI & Security Audit](https://github.com/WilkerDev1/libfprint-egismoc-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/WilkerDev1/libfprint-egismoc-rs/actions/workflows/ci.yml)
[![License: LGPL-2.1-or-later](https://img.shields.io/badge/License-LGPL_2.1--or--later-blue.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org/)

A memory-safe, **Sans-I/O Rust driver core** and **Microsoft SDCP (Secure Device Connection Protocol)** implementation for **Egis Technology (LighTuning) Match-on-Chip** fingerprint sensors (`1c7a:0582` – `1c7a:05a5`), statically linked into `libfprint-2.so.2.0.0` via a minimalist C GObject bridge.

Tested and verified on **Samsung Galaxy Book2 Pro 360 (`930QED`, sensor `1c7a:0582` `ETU905A80-E`)** running Arch Linux (GNOME Lock Screen / GDM, `sudo`, Polkit, and `fprintd`).

---

## Why Rewrite the Driver in Rust?

The original C reference implementation (`libfprint-egismoc-sdcp`) combines manual USB buffer assembly, OpenSSL `EVP_*` boilerplate, and three nested `FpiSsm` callback state machines (`task_ssm`, `cmd_ssm`, `wait_finger_ssm`) across ~4,455 lines of C. In real-world daily usage on Linux laptops, this led to critical failure modes:

1. **Immediate `sudo` failures after USB reset / autosuspend (`SDCP AuthorizedIdentity verification failed`)**:
   When the USB port resets (`g_usb_device_reset` on device open or kernel USB power management), the sensor loses its volatile SDCP `application_secret` in RAM while `fprintd` still holds a cached `sdcp-claim` on disk. When the user touches the sensor, the hardware chip **successfully matches the fingerprint in flash memory** and returns the 32-byte `enrollment_id`, but the C driver aborts the entire verification on the first try (`FP_DEVICE_ERROR_DATA_INVALID`) because the volatile session MAC no longer matches the stale cache.
2. **`fprintd` crashes (`SIGABRT`) on cancelled prompts (`assertion failed: (self->task_ssm == NULL)`)**:
   Cancelling an active fingerprint wait (e.g., pressing `Ctrl+C` in `sudo` or unlocking GNOME with a password while the sensor is waiting for a finger) left a dangling `self->task_ssm` pointer in the C driver, causing the next `egismoc_open()` call to crash `fprintd` with `SIGABRT`.

`libfprint-egismoc-rs` solves these issues at the architectural level by moving **100% of the state machines, packet framing, ASN.1 parsing, and SDCP cryptography into safe, deterministic Rust (`egismoc-core`)**.

---

## Comparison: Original C Driver vs. `libfprint-egismoc-rs`

| Feature / Metric | Original C Reference Driver (`libfprint-egismoc-sdcp`) | **`libfprint-egismoc-rs` (Rust Core + C Bridge)** |
| :--- | :--- | :--- |
| **C Code Attack Surface** | **4,455 LoC** (`egismoc.c/.h` + `fpi-sdcp-device.c/.h`) with manual pointer arithmetic and `memcpy`. | **669 LoC** thin GObject/USB shim (**-85% reduction in C code**). Zero `unsafe` blocks in protocol or state machine modules. |
| **State Machine & Cancellation** | 3 nested `FpiSsm` callback chains (`task_ssm`, `cmd_ssm`, `wait_finger_ssm`). Prone to `SIGABRT` (`self->task_ssm == NULL`) when cancelled mid-wait. | **Single Sans-I/O Rust `enum TaskState`** driven by `step()`. Cancellation is simply `self.task = None`—dangling states are impossible by construction. |
| **USB Reset & Autosuspend Recovery** | Fails immediately on first `sudo` attempt (`Device SDCP Identify response was not valid`) and stays broken until `sdcp-claim` expires (24h) or reboot. | **Self-healing SDCP channel**: accepts the hardware-verified 32-byte `enrollment_id` on `MacMismatchAfterReset` **and automatically invalidates the stale `sdcp-claim`** so the next operation performs a fresh `SDCP Connect` handshake. |
| **Enrollment after USB Reset** | Skips `SDCP Connect` during enrollment if a stale `sdcp-claim` exists on disk, causing `EnrollCommit` rejection. | Always performs a fresh `SDCP Connect` key agreement during hardware enrollment so `enrollment_id` generation is 100% synchronized with the sensor. |
| **ASN.1 DER & Packet Parsing** | Uses `g_assert()` on raw USB bytes (`fpi_sdcp_get_cert_length_from_buf`), crashing `fprintd` on truncated/malformed packets. | Bounds-checked slices + `checked_add` arithmetic returning typed `Result<_, SdcpError>`—never panics or aborts on malformed USB input. |
| **Cryptographic RAM Hygiene** | `fpi_sdcp_device_finalize()` frees heap buffers with `g_free()` without scrubbing ECDH private keys or `application_secret` in RAM. | Implements `Drop` on `SdcpSession` using `std::ptr::write_volatile` + `compiler_fence(Ordering::SeqCst)` to deterministically zeroize all private keys and derived secrets in RAM. |
| **MAC Verification Timing** | Standard `memcmp()` (vulnerable to timing side-channels). | Constant-time 32-byte XOR accumulator (`constant_time_eq_32`). |
| **SDCP Claim Cache Security** | Default permissions when falling back to `/tmp/.libfprint`. | Enforces `0700` directory and `0600` file permissions via `OpenOptionsExt::mode`, validates `/proc/sys/kernel/random/boot_id`, and checks 24h monotonic uptime expiration. |
| **Performance & Memory Allocations** | Heap allocations (`g_malloc0` / `g_free` / `FpiByteWriter`) on every command and cryptographic step. | Stack-allocated fixed arrays (`[u8; 32]`, `[u8; 65]`), vectorized 16-bit checksum loop via `buf.as_chunks::<2>()`, hardware SHA-NI acceleration, compiled with `lto = "thin"`, `codegen-units = 1`, and `panic = "abort"`. |

---

## Sans-I/O Architecture

```text
┌───────────────────────────────────────────────────────────────────────────┐
│                         libfprint-2.so.2.0.0                              │
│                                                                           │
│  ┌─────────────────────────────────┐      ┌────────────────────────────┐  │
│  │   GObject Bridge (c-bridge/)    │      │  egismoc-core (Rust .a)    │  │
│  │   egismoc.c (~639 LoC)          │      │                            │  │
│  │                                 │ step │  • state.rs (Sans-I/O)     │  │
│  │  • Registers FpiDeviceEgisMoc   ├─────►│    TaskState::Probe/List/  │  │
│  │  • Dispatches FpiUsbTransfer    │      │    Identify/Enroll/Delete  │  │
│  │    (Control / Bulk / Interrupt) │◄─────┤  • protocol.rs             │  │
│  │  • Reports to libfprint         │Action│    EGIS Framing + Checksum │  │
│  │    (progress, match, errors)    │      │  • sdcp.rs                 │  │
│  └─────────────────────────────────┘      │    ECDH P-256 + KBKDF      │  │
│                                           └────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Supported Devices

| USB VID:PID | Check Prefix Variant | Enrollment Stages | Known Laptop Models |
| :---: | :---: | :---: | :--- |
| **`1c7a:0582`** | Type 1 (`50 17 03 00 00`) | 10 | Samsung Galaxy Book2 Pro / Pro 360 (`ETU905A80-E`) |
| **`1c7a:0583`** | Type 1 (`50 17 03 00 00`) | 15 | Samsung Galaxy Book series |
| **`1c7a:0584`** | Type 1 (`50 17 03 00 00`) | 20 | Samsung Galaxy Book3 / Book4 series |
| **`1c7a:0586`** | Type 1 (`50 17 03 00 00`) | 20 | Samsung Galaxy Book series |
| **`1c7a:0587`** | Type 1 (`50 17 03 00 00`) | 20 | Samsung Galaxy Book series |
| **`1c7a:05a1`** | Type 2 (`50 17 03 80 00`) | 10 | Newer Egis Match-on-Chip laptops |
| **`1c7a:05a5`** | Type 2 (`50 17 03 80 00`) | 15 | Newer Egis Match-on-Chip laptops |

---

## Installation (Arch Linux)

### Option 1: Build from the `aur/` directory
```bash
git clone https://github.com/WilkerDev1/libfprint-egismoc-rs.git
cd libfprint-egismoc-rs/aur
makepkg -si
sudo systemctl restart fprintd.service
```

### Recommended PAM Configuration for Arch Linux (`/etc/pam.d/sudo` & `/etc/pam.d/system-auth`)

1. Add `pam_fprintd.so` to `/etc/pam.d/sudo`:
   ```text
   #%PAM-1.0
   auth      sufficient    pam_fprintd.so max-tries=3 timeout=10
   auth      include       system-auth
   account   include       system-auth
   session   include       system-auth
   ```
2. Prevent cancelled password prompts (such as GNOME cancelling `gdm-password` when `gdm-fingerprint` succeeds, or pressing `Ctrl+C` in `sudo`) from incrementing `pam_faillock` in `/etc/pam.d/system-auth`:
   ```text
   auth       [success=1 conv_err=die authinfo_unavail=die default=bad]     pam_unix.so          try_first_pass nullok
   ```

---

## Running Tests

### 1. Rust Core Unit Tests (`cargo test`)
Tests 16-bit one's complement checksums (even and odd payloads), packet builders, SP800-108 Counter Mode KBKDF vectors, ECDH P-256 key agreement, `ConnectResponse` / `ReconnectResponse` / `AuthorizedIdentity` MAC verification, USB reset auto-healing, and full state machine flows:
```bash
cd egismoc-core
cargo test
cargo clippy --all-targets -- -D warnings
```

### 2. `libfprint` + `umockdev` USB Emulation Suite (`meson test`)
Validates the compiled `libfprint-2.so.2.0.0` (linked with `libegismoc_core.a`) against real captured USB traffic (`custom.pcapng`):
```bash
meson test -C pkg_build --print-errorlogs
```

---

## Repository Structure

| Path | Description |
| :--- | :--- |
| [`egismoc-core/src/sdcp.rs`](egismoc-core/src/sdcp.rs) | Pure-Rust Microsoft SDCP implementation: ECDH P-256, SP800-108 Counter KBKDF (`HMAC-SHA256`), ASN.1 DER length parser, `Drop` zeroization, and `MacMismatchAfterReset` self-healing. |
| [`egismoc-core/src/protocol.rs`](egismoc-core/src/protocol.rs) | Command constants, `EGIS`/`SIGE` framing, 16-bit one's complement checksum (`egismoc_write_check_bytes`), and response parsers. |
| [`egismoc-core/src/state.rs`](egismoc-core/src/state.rs) | Deterministic Sans-I/O state machine (`Probe`, `List`, `Identify`, `Enroll`, `Delete`, `ClearStorage`). |
| [`egismoc-core/src/ffi.rs`](egismoc-core/src/ffi.rs) | C ABI (`extern "C"`) boundary exported as `libegismoc_core.a`. |
| [`egismoc-core/include/egismoc_rs.h`](egismoc-core/include/egismoc_rs.h) | C header defining `EgisMocRs`, `EgisMocAction`, and FFI entry points. |
| [`c-bridge/egismoc.c`](c-bridge/egismoc.c) | Minimalist `libfprint` GObject bridge dispatching `FpiUsbTransfer` actions for `egismoc-core`. |
| [`patches/meson-egismoc-rs.patch`](patches/meson-egismoc-rs.patch) | Meson build patch linking `libegismoc_core.a` into `libfprint`. |
| [`aur/PKGBUILD`](aur/PKGBUILD) | Standalone Arch User Repository (`AUR`) build script. |

---

## Credits & License

- Protocol reverse-engineering and original C driver work by **Joshua Grisham** ([`joshuagrisham`](https://github.com/joshuagrisham)) and **TenSeventy7** ([`libfprint-egismoc-sdcp`](https://github.com/TenSeventy7/libfprint-egismoc-sdcp)).
- Rust Sans-I/O core, SDCP auto-healing, and GObject bridge by **WilkerDev1**.
- Licensed under **LGPL-2.1-or-later**.
