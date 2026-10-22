# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `main` (`0.1.x`) | :white_check_mark: Active |

## Security Architecture

`libfprint-egismoc-rs` implements **Microsoft SDCP (Secure Device Connection Protocol)** in userspace for Egis Technology Match-on-Chip biometric sensors (`1c7a:0582` – `1c7a:05a5`):

- **Memory Isolation (Sans-I/O in Rust)**: All USB packet framing, ASN.1 DER length validation (`cert_m`), SP800-108 Counter Mode KBKDF (`HMAC-SHA256`), and ECDH `P-256` key agreement are written in safe Rust with zero `unsafe` blocks in the protocol or state-machine modules.
- **Deterministic RAM Zeroization (`Drop`)**: `SdcpSession` overwrites ephemeral private keys (`host_private_key`), `key_agreement`, `master_secret`, and `application_secret` with zeros (`write_volatile` + `compiler_fence(Ordering::SeqCst)`) when dropped or invalidated.
- **Constant-Time MAC Verification**: All 32-byte HMAC-SHA256 tags (`ConnectResponse`, `ReconnectResponse`, and `AuthorizedIdentity`) are compared in constant time (`constant_time_eq_32`).
- **Hardened Cache File Permissions**: Cached SDCP claims (`/var/lib/fprint/egismoc/<serial>/sdcp-claim`) are written with strict `0600` file permissions (and `0700` directory permissions), validated against `/proc/sys/kernel/random/boot_id`, and expire after 24 hours of monotonic uptime.

## Reporting a Vulnerability

If you discover a security issue (e.g., in USB frame parsing, SDCP session handling, or the FFI boundary), **please do not open a public issue**.

Instead, report it privately via **[Security → Report a vulnerability](https://github.com/WilkerDev1/libfprint-egismoc-rs/security/advisories/new)** (GitHub Private Vulnerability Reporting).
