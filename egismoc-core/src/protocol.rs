//! Constantes de protocolo, construcción de tramas con prefijo `EGIS`, cálculo de checksum
//! de 16 bits en complemento a uno (`egismoc_write_check_bytes`) y parseadores de respuestas
//! para lectores de huellas Egis Technology Match-on-Chip (`1c7a:0582` y familia).

use crate::sdcp::{SDCP_DIGEST_SIZE, SDCP_ENROLLMENT_ID_SIZE, SDCP_NONCE_SIZE, SDCP_PUBLIC_KEY_SIZE, SDCP_RANDOM_SIZE};

pub const EGISMOC_DRIVER_FULLNAME: &str = "Egis Technology (LighTuning) Match-on-Chip";

pub const EGISMOC_DRIVER_CHECK_PREFIX_TYPE1: u64 = 1 << 0;
pub const EGISMOC_DRIVER_CHECK_PREFIX_TYPE2: u64 = 1 << 1;
pub const EGISMOC_DRIVER_MAX_ENROLL_STAGES_20: u64 = 1 << 2;
pub const EGISMOC_DRIVER_MAX_ENROLL_STAGES_15: u64 = 1 << 3;

pub const EGISMOC_EP_CMD_OUT: u8 = 0x02;
pub const EGISMOC_EP_CMD_IN: u8 = 0x81;
pub const EGISMOC_EP_CMD_INTERRUPT_IN: u8 = 0x83;

pub const EGISMOC_USB_CONTROL_TIMEOUT: u32 = 5000;
pub const EGISMOC_USB_SEND_TIMEOUT: u32 = 5000;
pub const EGISMOC_USB_RECV_TIMEOUT: u32 = 5000;
pub const EGISMOC_USB_INTERRUPT_TIMEOUT: u32 = 60000;

pub const EGISMOC_USB_IN_RECV_LENGTH: usize = 4096;
pub const EGISMOC_USB_INTERRUPT_IN_RECV_LENGTH: usize = 64;

pub const EGISMOC_MAX_ENROLL_STAGES_DEFAULT: i32 = 10;
pub const EGISMOC_MAX_ENROLL_NUM: usize = 10;

pub const EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE: usize = 15;
pub const EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE: usize = 14;
pub const EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE: usize = 14;
pub const EGISMOC_LIST_RESPONSE_PREFIX_SIZE: usize = 14;
pub const EGISMOC_LIST_RESPONSE_SUFFIX_SIZE: usize = 2;
pub const EGISMOC_CHECK_BYTES_LENGTH: usize = 2;

/// Prefijo estándar de escritura hacia el sensor (`"EGIS" || 0x00000001`).
pub const EGISMOC_WRITE_PREFIX: [u8; 8] = [0x45, 0x47, 0x49, 0x53, 0x00, 0x00, 0x00, 0x01];

/// Prefijo estándar de lectura desde el sensor (`"SIGE" || 0x00000001`).
pub const EGISMOC_READ_PREFIX: [u8; 8] = [0x53, 0x49, 0x47, 0x45, 0x00, 0x00, 0x00, 0x01];

/* Payloads de comandos estáticos (egismoc.h) */

pub const CMD_FW_VERSION: [u8; 11] = [
    0x00, 0x00, 0x00, 0x07, 0x50, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x0c,
];
pub const RSP_FW_VERSION_SUFFIX: [u8; 2] = [0x90, 0x00];

pub const RSP_SENSOR_HAS_FINGER_SUFFIX: [u8; 4] = [0x90, 0x00, 0x90, 0x00];

pub const CMD_LIST: [u8; 11] = [
    0x00, 0x00, 0x00, 0x07, 0x50, 0x19, 0x04, 0x00, 0x00, 0x01, 0x40,
];

pub const CMD_SENSOR_RESET: [u8; 8] = [0x00, 0x00, 0x00, 0x04, 0x50, 0x1a, 0x00, 0x00];

pub const CMD_SENSOR_CHECK: [u8; 8] = [0x00, 0x00, 0x00, 0x04, 0x50, 0x17, 0x02, 0x00];

pub const CMD_SENSOR_IDENTIFY: [u8; 8] = [0x00, 0x00, 0x00, 0x04, 0x50, 0x17, 0x01, 0x01];
pub const RSP_IDENTIFY_MATCH_SUFFIX: [u8; 2] = [0x90, 0x00];
pub const RSP_IDENTIFY_NOTMATCH_SUFFIX: [u8; 2] = [0x90, 0x04];

pub const CMD_SENSOR_ENROLL: [u8; 8] = [0x00, 0x00, 0x00, 0x04, 0x50, 0x17, 0x01, 0x00];

pub const CMD_ENROLL_STARTING: [u8; 11] = [
    0x00, 0x00, 0x00, 0x07, 0x50, 0x16, 0x01, 0x00, 0x00, 0x00, 0x20,
];
pub const RSP_ENROLL_STARTING_SUFFIX: [u8; 2] = [0x90, 0x00];

pub const CMD_SENSOR_START_CAPTURE: [u8; 8] = [0x00, 0x00, 0x00, 0x04, 0x50, 0x16, 0x02, 0x01];

pub const CMD_CAPTURE_POST_WAIT_FINGER: [u8; 11] = [
    0x00, 0x00, 0x00, 0x07, 0x50, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x80,
];

pub const CMD_READ_CAPTURE: [u8; 11] = [
    0x00, 0x00, 0x00, 0x07, 0x50, 0x16, 0x02, 0x02, 0x00, 0x00, 0x02,
];
pub const RSP_READ_SUCCESS_SUFFIX: [u8; 2] = [0x90, 0x00];
pub const RSP_READ_OFFCENTER_SUFFIX: [u8; 2] = [0x64, 0x91];
pub const RSP_READ_DIRTY_PREFIX: [u8; 5] = [0x00, 0x00, 0x00, 0x02, 0x64];

pub const CMD_COMMIT_STARTING: [u8; 11] = [
    0x00, 0x00, 0x00, 0x07, 0x50, 0x16, 0x05, 0x00, 0x00, 0x00, 0x20,
];
pub const RSP_COMMIT_SUCCESS_SUFFIX: [u8; 2] = [0x90, 0x00];

/* Prefijos y sufijos para payloads dinámicos */

pub const CMD_SDCP_CONNECT_PREFIX: [u8; 12] = [
    0x00, 0x00, 0x00, 0x6b, 0x50, 0x57, 0x01, 0x00, 0x00, 0x00, 0x62, 0x20,
];
pub const CMD_SDCP_CONNECT_SUFFIX: [u8; 2] = [0x00, 0x00];
pub const RSP_SDCP_CONNECT_SUCCESS_SUFFIX: [u8; 2] = [0x90, 0x00];

pub const CMD_NEW_PRINT_PREFIX: [u8; 11] = [
    0x00, 0x00, 0x00, 0x27, 0x50, 0x16, 0x03, 0x00, 0x00, 0x00, 0x20,
];

pub const CMD_DELETE_PREFIX: [u8; 5] = [0x50, 0x18, 0x04, 0x00, 0x00];
pub const RSP_DELETE_SUCCESS_PREFIX: [u8; 6] = [0x00, 0x00, 0x00, 0x02, 0x90, 0x00];

pub const CMD_CHECK_PREFIX_TYPE1: [u8; 5] = [0x50, 0x17, 0x03, 0x00, 0x00];
pub const CMD_CHECK_PREFIX_TYPE2: [u8; 5] = [0x50, 0x17, 0x03, 0x80, 0x00];
pub const CMD_CHECK_SUFFIX: [u8; 2] = [0x00, 0x40];
pub const RSP_CHECK_NOT_YET_ENROLLED_SUFFIX: [u8; 2] = [0x90, 0x04];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    PacketTooShort,
    InvalidPrefix,
    InvalidSuffix,
    UnrecognizedResponse,
}

/// Resultado de `identify_check` tras comparar contra las plantillas en el chip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyCheckResult {
    /// El chip encontró una huella coincidente.
    /// Nota: en EgisMoc el dispositivo envía primero `device_mac` (32B) y luego `enrollment_id` (32B).
    Match {
        device_mac: [u8; SDCP_DIGEST_SIZE],
        enrollment_id: [u8; SDCP_ENROLLMENT_ID_SIZE],
    },
    /// El chip respondió `90 04` (sin coincidencia).
    NoMatch,
}

/// Resultado de una captura parcial durante `Enroll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureReadStatus {
    /// Captura parcial exitosa (`90 00`).
    Success,
    /// Dedo descentrado (`64 91`).
    OffCenter,
    /// Sensor sucio (`00 00 00 02 64`).
    DirtySensor,
    /// Otro fallo recuperable de lectura.
    RetryUnknown,
}

/// Calcula exactamente los 2 bytes de verificación (`egismoc_write_check_bytes` / `egismoc_get_check_bytes`)
/// en complemento a uno de 16 bits (`0xFFFF - (sum % 0xFFFF)`).
///
/// Si el buffer tiene longitud impar, replica el comportamiento de `fpi_byte_writer_init_with_size`
/// en C añadiendo un byte `0x00` virtual al final para completar la última palabra big-endian de 16 bits.
pub fn egismoc_write_check_bytes(buf: &[u8]) -> u16 {
    let mut sum_values: usize = 0;
    let (chunks, remainder) = buf.as_chunks::<2>();
    for &pair in chunks {
        let word = u16::from_be_bytes(pair) as usize;
        sum_values += word;
    }
    if let Some(&last_byte) = remainder.first() {
        let word = u16::from_be_bytes([last_byte, 0x00]) as usize;
        sum_values += word;
    }
    (0xFFFFusize - (sum_values % 0xFFFFusize)) as u16
}

/// Construye una trama completa lista para enviarse por Bulk OUT (`EP 0x02`):
/// `EGIS (4B) || 00 00 00 01 (4B) || check_bytes (2B BE) || payload`.
pub fn wrap_egui_frame(payload: &[u8]) -> Vec<u8> {
    let total_len = EGISMOC_WRITE_PREFIX.len() + EGISMOC_CHECK_BYTES_LENGTH + payload.len();
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&EGISMOC_WRITE_PREFIX);
    frame.extend_from_slice(&[0x00, 0x00]); // Placeholder para check bytes
    frame.extend_from_slice(payload);

    let check = egismoc_write_check_bytes(&frame);
    let check_be = check.to_be_bytes();
    frame[8] = check_be[0];
    frame[9] = check_be[1];
    frame
}

/// Valida que el payload leído comience (después de los 8 bytes `SIGE...` y 2 check bytes) con `valid_prefix`.
pub fn validate_response_prefix(buffer_in: &[u8], valid_prefix: &[u8]) -> bool {
    let start = EGISMOC_READ_PREFIX.len() + EGISMOC_CHECK_BYTES_LENGTH;
    if buffer_in.len() < start + valid_prefix.len() {
        return false;
    }
    &buffer_in[start..start + valid_prefix.len()] == valid_prefix
}

/// Valida que la trama recibida termine exactamente con `valid_suffix`.
pub fn validate_response_suffix(buffer_in: &[u8], valid_suffix: &[u8]) -> bool {
    if buffer_in.len() < valid_suffix.len() {
        return false;
    }
    &buffer_in[buffer_in.len() - valid_suffix.len()..] == valid_suffix
}

/// Verifica si una transferencia Interrupt IN (`EP 0x83`) indica dedo presente en el sensor:
/// comienza con `"SIGE"` y termina con `90 00 90 00`.
pub fn is_finger_present_interrupt(buffer_in: &[u8]) -> bool {
    buffer_in.len() >= 4
        && &buffer_in[..4] == b"SIGE"
        && validate_response_suffix(buffer_in, &RSP_SENSOR_HAS_FINGER_SUFFIX)
}

/// Construye el payload (sin envolver) del comando SDCP `Connect` (`egismoc_get_sdcp_connect_cmd`).
pub fn build_sdcp_connect_payload(
    host_random: &[u8; SDCP_RANDOM_SIZE],
    host_public_key: &[u8; SDCP_PUBLIC_KEY_SIZE],
) -> Vec<u8> {
    let len = CMD_SDCP_CONNECT_PREFIX.len()
        + SDCP_RANDOM_SIZE
        + SDCP_PUBLIC_KEY_SIZE
        + CMD_SDCP_CONNECT_SUFFIX.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&CMD_SDCP_CONNECT_PREFIX);
    out.extend_from_slice(host_random);
    out.extend_from_slice(host_public_key);
    out.extend_from_slice(&CMD_SDCP_CONNECT_SUFFIX);
    out
}

/// Construye el payload (sin envolver) del comando `Delete` (`egismoc_get_delete_cmd`)
/// para uno o varios `enrollment_id` de 32 bytes.
pub fn build_delete_payload(ids_to_delete: &[[u8; SDCP_ENROLLMENT_ID_SIZE]]) -> Vec<u8> {
    let num = ids_to_delete.len();
    let total_len = 6 + CMD_DELETE_PREFIX.len() + SDCP_ENROLLMENT_ID_SIZE * num;
    let mut out = Vec::with_capacity(total_len);

    // 1) 00 00
    out.extend_from_slice(&[0x00, 0x00]);

    // 2) 2-byte size indicator: num * 0x20 + 0x07
    if num > 7 {
        out.push(0x01);
        out.push((((num - 8) * 0x20) + 0x07) as u8);
    } else {
        out.push(0x00);
        out.push(((num * 0x20) + 0x07) as u8);
    }

    // 3) cmd_delete_prefix
    out.extend_from_slice(&CMD_DELETE_PREFIX);

    // 4) 2-byte size indicator: num * 0x20
    if num > 7 {
        out.push(0x01);
        out.push(((num - 8) * 0x20) as u8);
    } else {
        out.push(0x00);
        out.push((num * 0x20) as u8);
    }

    // 5) identificadores de 32 bytes
    for id in ids_to_delete {
        out.extend_from_slice(id);
    }

    out
}

/// Construye el payload (sin envolver) del comando `Check` (`egismoc_get_check_cmd`)
/// usado tanto en `Enroll` (para detectar duplicados) como en `Identify`/`Verify`.
pub fn build_check_payload(
    enrolled_ids: &[[u8; SDCP_ENROLLMENT_ID_SIZE]],
    use_type2_prefix: bool,
) -> Vec<u8> {
    let num = enrolled_ids.len();
    let prefix: &[u8] = if use_type2_prefix {
        &CMD_CHECK_PREFIX_TYPE2
    } else {
        &CMD_CHECK_PREFIX_TYPE1
    };

    let total_len = 6
        + prefix.len()
        + SDCP_NONCE_SIZE
        + (num * SDCP_ENROLLMENT_ID_SIZE)
        + CMD_CHECK_SUFFIX.len();
    let mut out = Vec::with_capacity(total_len);

    // 1) 00 00
    out.extend_from_slice(&[0x00, 0x00]);

    // 2) 2-byte size counter: (num + 1) * 0x20 + 0x09
    if num > 6 {
        out.push(0x01);
        out.push((((num - 7) * 0x20) + 0x09) as u8);
    } else {
        out.push(0x00);
        out.push((((num + 1) * 0x20) + 0x09) as u8);
    }

    // 3) prefix según variante (Type1 vs Type2)
    out.extend_from_slice(prefix);

    // 4) 2-byte size counter: (num + 1) * 0x20
    if num > 6 {
        out.push(0x01);
        out.push(((num - 7) * 0x20) as u8);
    } else {
        out.push(0x00);
        out.push(((num + 1) * 0x20) as u8);
    }

    // 5) SDCP Identify nonce (32 bytes en 0x00 en estos sensores)
    out.extend_from_slice(&[0u8; SDCP_NONCE_SIZE]);

    // 6) Todos los enrollment_id registrados actualmente
    for id in enrolled_ids {
        out.extend_from_slice(id);
    }

    // 7) Sufijo 00 40
    out.extend_from_slice(&CMD_CHECK_SUFFIX);
    out
}

/// Construye el payload (sin envolver) para comprometer una nueva huella (`ENROLL_COMMIT`):
/// `cmd_new_print_prefix || enrollment_id(32B)`.
pub fn build_new_print_payload(enrollment_id: &[u8; SDCP_ENROLLMENT_ID_SIZE]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CMD_NEW_PRINT_PREFIX.len() + SDCP_ENROLLMENT_ID_SIZE);
    out.extend_from_slice(&CMD_NEW_PRINT_PREFIX);
    out.extend_from_slice(enrollment_id);
    out
}

/// Extrae la lista de `enrollment_id` de 32 bytes de la respuesta a `cmd_list`
/// (`egismoc_list_fill_enrolled_ids_cb`), excluyendo los 2 bytes de sufijo `90 00`.
pub fn parse_list_response(buffer_in: &[u8]) -> Result<Vec<[u8; SDCP_ENROLLMENT_ID_SIZE]>, ProtocolError> {
    if buffer_in.len() < EGISMOC_READ_PREFIX.len() {
        return Err(ProtocolError::PacketTooShort);
    }
    if buffer_in.len() < EGISMOC_LIST_RESPONSE_PREFIX_SIZE + EGISMOC_LIST_RESPONSE_SUFFIX_SIZE {
        return Ok(Vec::new());
    }

    let payload_end = buffer_in.len() - EGISMOC_LIST_RESPONSE_SUFFIX_SIZE;
    let mut ids = Vec::new();
    let mut pos = EGISMOC_LIST_RESPONSE_PREFIX_SIZE;
    while pos + SDCP_ENROLLMENT_ID_SIZE <= payload_end {
        let mut id = [0u8; SDCP_ENROLLMENT_ID_SIZE];
        id.copy_from_slice(&buffer_in[pos..pos + SDCP_ENROLLMENT_ID_SIZE]);
        ids.push(id);
        pos += SDCP_ENROLLMENT_ID_SIZE;
    }

    Ok(ids)
}

/// Parsea la respuesta del comando `identify_check` (`egismoc_identify_check_cb`).
pub fn parse_identify_check_response(buffer_in: &[u8]) -> Result<IdentifyCheckResult, ProtocolError> {
    if buffer_in.len() < EGISMOC_READ_PREFIX.len() {
        return Err(ProtocolError::PacketTooShort);
    }

    if validate_response_suffix(buffer_in, &RSP_IDENTIFY_MATCH_SUFFIX) {
        let min_len = EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE
            + SDCP_DIGEST_SIZE
            + SDCP_ENROLLMENT_ID_SIZE
            + RSP_IDENTIFY_MATCH_SUFFIX.len();
        if buffer_in.len() < min_len {
            return Err(ProtocolError::PacketTooShort);
        }

        let mut device_mac = [0u8; SDCP_DIGEST_SIZE];
        device_mac.copy_from_slice(
            &buffer_in[EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE
                ..EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE + SDCP_DIGEST_SIZE],
        );

        let id_start = EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE + SDCP_DIGEST_SIZE;
        let mut enrollment_id = [0u8; SDCP_ENROLLMENT_ID_SIZE];
        enrollment_id.copy_from_slice(&buffer_in[id_start..id_start + SDCP_ENROLLMENT_ID_SIZE]);

        Ok(IdentifyCheckResult::Match {
            device_mac,
            enrollment_id,
        })
    } else if validate_response_suffix(buffer_in, &RSP_IDENTIFY_NOTMATCH_SUFFIX) {
        Ok(IdentifyCheckResult::NoMatch)
    } else {
        Err(ProtocolError::UnrecognizedResponse)
    }
}

/// Extrae el `enrollment_nonce` de 32 bytes de la respuesta a `cmd_enroll_starting`.
pub fn parse_enroll_starting_response(buffer_in: &[u8]) -> Result<[u8; SDCP_NONCE_SIZE], ProtocolError> {
    if !validate_response_suffix(buffer_in, &RSP_ENROLL_STARTING_SUFFIX) {
        return Err(ProtocolError::InvalidSuffix);
    }
    let min_len = EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE
        + SDCP_NONCE_SIZE
        + RSP_ENROLL_STARTING_SUFFIX.len();
    if buffer_in.len() < min_len {
        return Err(ProtocolError::PacketTooShort);
    }

    let mut nonce = [0u8; SDCP_NONCE_SIZE];
    nonce.copy_from_slice(
        &buffer_in[EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE
            ..EGISMOC_ENROLL_STARTING_RESPONSE_PREFIX_SIZE + SDCP_NONCE_SIZE],
    );
    Ok(nonce)
}

/// Evalúa la respuesta a `cmd_read_capture` (`egismoc_read_capture_cb`).
pub fn parse_read_capture_response(buffer_in: &[u8]) -> CaptureReadStatus {
    if validate_response_suffix(buffer_in, &RSP_READ_SUCCESS_SUFFIX) {
        CaptureReadStatus::Success
    } else if validate_response_suffix(buffer_in, &RSP_READ_OFFCENTER_SUFFIX) {
        CaptureReadStatus::OffCenter
    } else if validate_response_prefix(buffer_in, &RSP_READ_DIRTY_PREFIX) {
        CaptureReadStatus::DirtySensor
    } else {
        CaptureReadStatus::RetryUnknown
    }
}

/// Extrae la cadena de versión de firmware de la respuesta a `cmd_fw_version`.
pub fn parse_fw_version_response(buffer_in: &[u8]) -> Result<String, ProtocolError> {
    if !validate_response_suffix(buffer_in, &RSP_FW_VERSION_SUFFIX) {
        return Err(ProtocolError::InvalidSuffix);
    }
    let prefix_len = EGISMOC_READ_PREFIX.len() + 2 + 3 + 1;
    if buffer_in.len() < prefix_len + RSP_FW_VERSION_SUFFIX.len() {
        return Err(ProtocolError::PacketTooShort);
    }
    let end = buffer_in.len() - RSP_FW_VERSION_SUFFIX.len();
    let slice = &buffer_in[prefix_len..end];
    let clean_end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..clean_end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_fw_version_and_cmd_list_wrapping_and_checksums() {
        // Verifica que el cálculo de checksum de 16 bits en complemento a uno
        // haga que la suma de palabras BE de 16 bits módulo 0xFFFF sea 0xFFFF (0 en complemento a 1).
        let fw_frame = wrap_egui_frame(&CMD_FW_VERSION);
        assert_eq!(&fw_frame[..8], &EGISMOC_WRITE_PREFIX);
        assert_eq!(&fw_frame[10..], &CMD_FW_VERSION);

        // Verificar que al recalcular sobre la trama con el checksum ya puesto:
        // sum % 0xFFFF == 0, por lo que 0xFFFF - (sum % 0xFFFF) == 0xFFFF (-0 en complemento a 1)
        assert_eq!(egismoc_write_check_bytes(&fw_frame), 0xFFFF);

        let list_frame = wrap_egui_frame(&CMD_LIST);
        assert_eq!(&list_frame[..8], &EGISMOC_WRITE_PREFIX);
        assert_eq!(&list_frame[10..], &CMD_LIST);
        assert_eq!(egismoc_write_check_bytes(&list_frame), 0xFFFF);

        // Valores exactos de check bytes para CMD_FW_VERSION y CMD_LIST:
        // EGIS (0x4547 + 0x4953) + 0x0000 + 0x0001 = 0x8E9B
        // CMD_FW_VERSION (11 bytes -> 12 con pad 0x00):
        // 0x0000 + 0x0007 + 0x507f + 0x0000 + 0x0000 + 0x0c00 = 0x5C86
        // Total sum = 0x8E9B + 0x5C86 = 0xEB21 -> 0xFFFF - 0xEB21 = 0x14DE
        assert_eq!(&fw_frame[8..10], &[0x14, 0xDE]);

        // CMD_LIST:
        // 0x0000 + 0x0007 + 0x5019 + 0x0400 + 0x0001 + 0x4000 = 0x9421
        // Total sum = 0x8E9B + 0x9421 = 0x122BC % 0xFFFF = 0x22BD
        // 0xFFFF - 0x22BD = 0xDD42
        assert_eq!(&list_frame[8..10], &[0xDD, 0x42]);
    }

    #[test]
    fn test_delete_cmd_and_new_print_cmd_and_check_cmd_byte_exact() {
        let id1 = [0xAAu8; 32];
        let id2 = [0xBBu8; 32];

        // Delete 1 print
        let del1 = build_delete_payload(&[id1]);
        assert_eq!(del1.len(), 6 + 5 + 32);
        assert_eq!(&del1[0..4], &[0x00, 0x00, 0x00, 0x27]);
        assert_eq!(&del1[4..9], &CMD_DELETE_PREFIX);
        assert_eq!(&del1[9..11], &[0x00, 0x20]);
        assert_eq!(&del1[11..43], &id1);

        // Delete 8 prints (verifica el salto a 2 bytes > 7 en egismoc.c)
        let ids8 = [id1; 8];
        let del8 = build_delete_payload(&ids8);
        assert_eq!(&del8[0..4], &[0x00, 0x00, 0x01, 0x07]);
        assert_eq!(&del8[9..11], &[0x01, 0x00]);

        // New print payload
        let new_print = build_new_print_payload(&id2);
        assert_eq!(new_print.len(), 11 + 32);
        assert_eq!(&new_print[..11], &CMD_NEW_PRINT_PREFIX);
        assert_eq!(&new_print[11..], &id2);

        // Check payload Type1 vs Type2
        let check1 = build_check_payload(&[id1, id2], false);
        assert_eq!(&check1[0..4], &[0x00, 0x00, 0x00, 0x69]);
        assert_eq!(&check1[4..9], &CMD_CHECK_PREFIX_TYPE1);
        assert_eq!(&check1[9..11], &[0x00, 0x60]);
        assert_eq!(&check1[11..43], &[0u8; 32]);
        assert_eq!(&check1[43..75], &id1);
        assert_eq!(&check1[75..107], &id2);
        assert_eq!(&check1[107..109], &CMD_CHECK_SUFFIX);

        let check2 = build_check_payload(&[id1], true);
        assert_eq!(&check2[4..9], &CMD_CHECK_PREFIX_TYPE2);
    }

    #[test]
    fn test_parse_list_and_identify_responses() {
        let id1 = [0x11u8; 32];
        let id2 = [0x22u8; 32];
        let mut list_rsp = vec![0u8; EGISMOC_LIST_RESPONSE_PREFIX_SIZE];
        list_rsp[..8].copy_from_slice(&EGISMOC_READ_PREFIX);
        list_rsp.extend_from_slice(&id1);
        list_rsp.extend_from_slice(&id2);
        list_rsp.extend_from_slice(&[0x90, 0x00]);

        let parsed_ids = parse_list_response(&list_rsp).unwrap();
        assert_eq!(parsed_ids, vec![id1, id2]);

        let mac = [0x55u8; 32];
        let mut id_rsp = vec![0u8; EGISMOC_IDENTIFY_RESPONSE_PREFIX_SIZE];
        id_rsp[..8].copy_from_slice(&EGISMOC_READ_PREFIX);
        id_rsp.extend_from_slice(&mac);
        id_rsp.extend_from_slice(&id1);
        id_rsp.extend_from_slice(&RSP_IDENTIFY_MATCH_SUFFIX);

        let parsed_ident = parse_identify_check_response(&id_rsp).unwrap();
        assert_eq!(
            parsed_ident,
            IdentifyCheckResult::Match {
                device_mac: mac,
                enrollment_id: id1,
            }
        );
    }
}
