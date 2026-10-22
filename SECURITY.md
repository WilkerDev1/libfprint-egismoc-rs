# Política de Seguridad (Security Policy)

## Versiones Soportadas

| Versión | Soporte de Seguridad |
| :--- | :--- |
| `main` (`0.1.x`) | :white_check_mark: Activo |

## Arquitectura de Seguridad del Driver

`libfprint-egismoc-rs` implementa el protocolo **Microsoft SDCP (Secure Device Connection Protocol)** en espacio de usuario para sensores biométricos Match-on-Chip Egis Technology (`1c7a:0582` – `1c7a:05a5`):

- **Aislamiento de memoria (Sans-I/O en Rust)**: Todo el parseo de paquetes USB, validación ASN.1 DER (`cert_m`), derivación de claves SP800-108 KBKDF (`HMAC-SHA256`) e intercambio ECDH `P-256` está escrito en Rust seguro sin bloques `unsafe` en los módulos de protocolo ni máquina de estados.
- **Borrado criptográfico en RAM (`Drop`)**: `SdcpSession` sobrescribe con ceros (`write_volatile` + `compiler_fence`) las claves privadas efímeras (`host_private_key`), `key_agreement`, `master_secret` y `application_secret` al cerrarse o invalidarse la sesión.
- **Comparación de MACs en tiempo constante**: Las etiquetas HMAC-SHA256 de `ConnectResponse`, `ReconnectResponse` y `AuthorizedIdentity` se verifican en tiempo constante (`constant_time_eq_32`).
- **Permisos estrictos en caché**: El archivo de sesión `/var/lib/fprint/egismoc/<serial>/sdcp-claim` se escribe con permisos `0600` (y directorio `0700`) y expira al cambiar `/proc/sys/kernel/random/boot_id` o tras 24 horas.

## Reportar una Vulnerabilidad

Si descubres una vulnerabilidad de seguridad (por ejemplo, en el parseo de tramas USB, manejo de sesiones SDCP o frontera FFI), **no abras un Issue público**.

Por favor repórtala de forma privada a través de la pestaña **[Security → Report a vulnerability](https://github.com/WilkerDev1/libfprint-egismoc-rs/security/advisories/new)** de este repositorio (GitHub Private Vulnerability Reporting).
