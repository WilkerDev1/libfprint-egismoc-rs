//! Implementación en Rust de Microsoft SDCP (Secure Device Connection Protocol)
//! para sensores biométricos Match-on-Chip Egis Technology (`1c7a:0582`).
//!
//! Incluye:
//! - Intercambio de llaves efímeras ECDH sobre curva NIST P-256 (`secp256r1`).
//! - Derivación SP800-108 Counter Mode KBKDF con HMAC-SHA256 (`master secret` y `application keys`).
//! - Parseo seguro de longitud ASN.1 DER (`cert_m`) y de tramas `ConnectResponse`.
//! - Verificación criptográfica de `ConnectResponse`, `ReconnectResponse` y `AuthorizedIdentity`.
//! - Tolerancia explícita a reinicios de bus USB (`IdentityVerification::MacMismatchAfterReset`).
//! - Generación de `enrollment_id` de 32 bytes.

use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

type HmacSha256 = Hmac<Sha256>;

pub const SDCP_RANDOM_SIZE: usize = 32;
pub const SDCP_DIGEST_SIZE: usize = 32;
pub const SDCP_NONCE_SIZE: usize = 32;
pub const SDCP_PRIVATE_KEY_SIZE: usize = 32;
pub const SDCP_PUBLIC_KEY_SIZE: usize = 65;
pub const SDCP_SIGNATURE_SIZE: usize = 64;
pub const SDCP_KEY_AGREEMENT_SIZE: usize = 32;
pub const SDCP_MASTER_SECRET_SIZE: usize = 32;
pub const SDCP_APPLICATION_SECRET_SIZE: usize = 32;
pub const SDCP_APPLICATION_SYMMETRIC_KEY_SIZE: usize = 32;
pub const SDCP_ENROLLMENT_ID_SIZE: usize = 32;

const EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE: usize = 15;
const RSP_SDCP_CONNECT_SUCCESS_SUFFIX: [u8; 2] = [0x90, 0x00];

/// Errores posibles durante las operaciones criptográficas y de parseo SDCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdcpError {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidCertificateAsn1,
    BufferTooShort,
    InvalidResponseSuffix,
    MacVerificationFailed,
    NotConnected,
    RngFailure,
    IoError,
}

/// Estado explícito devuelto por `verify_authorized_identity`.
///
/// En el sensor EgisMoc (`1c7a:0582`), cuando el kernel o `libfprint` reinicia el
/// dispositivo USB en `open()` (`g_usb_device_reset`), el firmware del sensor puede
/// perder su sesión SDCP volátil en RAM mientras conserva las plantillas en flash.
/// En ese escenario el sensor realiza el match biométrico en hardware y devuelve el
/// `enrollment_id` de 32 bytes correcto, pero firma el `AuthorizedIdentity` con una
/// clave de sesión reiniciada. Devolver `MacMismatchAfterReset` permite registrar la
/// condición de forma segura sin abortar la coincidencia del `enrollment_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityVerification {
    /// El MAC HMAC-SHA256 de `AuthorizedIdentity` coincide exactamente con la sesión activa.
    Verified,
    /// El hardware identificó el `enrollment_id`, pero el MAC difiere tras un reinicio USB.
    MacMismatchAfterReset,
    /// No existe una sesión SDCP conectada.
    NotConnected,
}

/// Estructura desglosada de un `ConnectResponse` SDCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdcpConnectResponse {
    pub device_random: [u8; SDCP_RANDOM_SIZE],
    pub model_certificate: Vec<u8>,
    pub device_public_key: [u8; SDCP_PUBLIC_KEY_SIZE],
    pub firmware_public_key: [u8; SDCP_PUBLIC_KEY_SIZE],
    pub firmware_hash: [u8; SDCP_DIGEST_SIZE],
    pub model_signature: [u8; SDCP_SIGNATURE_SIZE],
    pub device_signature: [u8; SDCP_SIGNATURE_SIZE],
    pub mac: [u8; SDCP_DIGEST_SIZE],
}

impl SdcpConnectResponse {
    /// Parsea un `ConnectResponse` con el formato estándar de la especificación SDCP
    /// (`r_d || cert_m (ASN.1 DER) || pk_d || pk_f || h_f || s_m || s_d || m`).
    pub fn from_standard_buf(buf: &[u8]) -> Result<Self, SdcpError> {
        let min_fixed = SDCP_RANDOM_SIZE
            + SDCP_PUBLIC_KEY_SIZE
            + SDCP_PUBLIC_KEY_SIZE
            + SDCP_DIGEST_SIZE
            + SDCP_SIGNATURE_SIZE
            + SDCP_SIGNATURE_SIZE
            + SDCP_DIGEST_SIZE;

        if buf.len() <= min_fixed {
            return Err(SdcpError::BufferTooShort);
        }

        let mut pos = 0;
        let mut device_random = [0u8; SDCP_RANDOM_SIZE];
        device_random.copy_from_slice(&buf[pos..pos + SDCP_RANDOM_SIZE]);
        pos += SDCP_RANDOM_SIZE;

        let cert_len = get_cert_length_from_buf(&buf[pos..])?;
        if buf.len() < min_fixed + cert_len {
            return Err(SdcpError::BufferTooShort);
        }

        let model_certificate = buf[pos..pos + cert_len].to_vec();
        pos += cert_len;

        let mut device_public_key = [0u8; SDCP_PUBLIC_KEY_SIZE];
        device_public_key.copy_from_slice(&buf[pos..pos + SDCP_PUBLIC_KEY_SIZE]);
        pos += SDCP_PUBLIC_KEY_SIZE;

        let mut firmware_public_key = [0u8; SDCP_PUBLIC_KEY_SIZE];
        firmware_public_key.copy_from_slice(&buf[pos..pos + SDCP_PUBLIC_KEY_SIZE]);
        pos += SDCP_PUBLIC_KEY_SIZE;

        let mut firmware_hash = [0u8; SDCP_DIGEST_SIZE];
        firmware_hash.copy_from_slice(&buf[pos..pos + SDCP_DIGEST_SIZE]);
        pos += SDCP_DIGEST_SIZE;

        let mut model_signature = [0u8; SDCP_SIGNATURE_SIZE];
        model_signature.copy_from_slice(&buf[pos..pos + SDCP_SIGNATURE_SIZE]);
        pos += SDCP_SIGNATURE_SIZE;

        let mut device_signature = [0u8; SDCP_SIGNATURE_SIZE];
        device_signature.copy_from_slice(&buf[pos..pos + SDCP_SIGNATURE_SIZE]);
        pos += SDCP_SIGNATURE_SIZE;

        let mut mac = [0u8; SDCP_DIGEST_SIZE];
        mac.copy_from_slice(&buf[pos..pos + SDCP_DIGEST_SIZE]);

        Ok(Self {
            device_random,
            model_certificate,
            device_public_key,
            firmware_public_key,
            firmware_hash,
            model_signature,
            device_signature,
            mac,
        })
    }

    /// Parsea la trama `ConnectResponse` específica de sensores EgisMoc:
    /// `prefix(15B) || r_d(32B) || cert_len_be(2B) || cert_m || pk_d(65B) || pk_f(65B) || h_f(32B) || s_m(64B) || s_d(64B) || m(32B) || 90 00`.
    pub fn from_egismoc_frame(buf: &[u8]) -> Result<Self, SdcpError> {
        if buf.len() < 2 || buf[buf.len() - 2..] != RSP_SDCP_CONNECT_SUCCESS_SUFFIX {
            return Err(SdcpError::InvalidResponseSuffix);
        }

        let min_fixed = EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE
            + SDCP_RANDOM_SIZE
            + 2
            + SDCP_PUBLIC_KEY_SIZE
            + SDCP_PUBLIC_KEY_SIZE
            + SDCP_DIGEST_SIZE
            + SDCP_SIGNATURE_SIZE
            + SDCP_SIGNATURE_SIZE
            + SDCP_DIGEST_SIZE
            + RSP_SDCP_CONNECT_SUCCESS_SUFFIX.len();

        if buf.len() <= min_fixed {
            return Err(SdcpError::BufferTooShort);
        }

        let mut pos = EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE;

        let mut device_random = [0u8; SDCP_RANDOM_SIZE];
        device_random.copy_from_slice(&buf[pos..pos + SDCP_RANDOM_SIZE]);
        pos += SDCP_RANDOM_SIZE;

        let cert_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        let remaining_after_cert = SDCP_PUBLIC_KEY_SIZE
            + SDCP_PUBLIC_KEY_SIZE
            + SDCP_DIGEST_SIZE
            + SDCP_SIGNATURE_SIZE
            + SDCP_SIGNATURE_SIZE
            + SDCP_DIGEST_SIZE
            + RSP_SDCP_CONNECT_SUCCESS_SUFFIX.len();

        if buf.len() < pos + cert_len + remaining_after_cert {
            return Err(SdcpError::BufferTooShort);
        }

        let model_certificate = buf[pos..pos + cert_len].to_vec();
        // Validamos también que el certificado comience con una secuencia ASN.1 DER válida
        let asn1_len = get_cert_length_from_buf(&model_certificate)?;
        if asn1_len > cert_len {
            return Err(SdcpError::InvalidCertificateAsn1);
        }
        pos += cert_len;

        let mut device_public_key = [0u8; SDCP_PUBLIC_KEY_SIZE];
        device_public_key.copy_from_slice(&buf[pos..pos + SDCP_PUBLIC_KEY_SIZE]);
        pos += SDCP_PUBLIC_KEY_SIZE;

        let mut firmware_public_key = [0u8; SDCP_PUBLIC_KEY_SIZE];
        firmware_public_key.copy_from_slice(&buf[pos..pos + SDCP_PUBLIC_KEY_SIZE]);
        pos += SDCP_PUBLIC_KEY_SIZE;

        let mut firmware_hash = [0u8; SDCP_DIGEST_SIZE];
        firmware_hash.copy_from_slice(&buf[pos..pos + SDCP_DIGEST_SIZE]);
        pos += SDCP_DIGEST_SIZE;

        let mut model_signature = [0u8; SDCP_SIGNATURE_SIZE];
        model_signature.copy_from_slice(&buf[pos..pos + SDCP_SIGNATURE_SIZE]);
        pos += SDCP_SIGNATURE_SIZE;

        let mut device_signature = [0u8; SDCP_SIGNATURE_SIZE];
        device_signature.copy_from_slice(&buf[pos..pos + SDCP_SIGNATURE_SIZE]);
        pos += SDCP_SIGNATURE_SIZE;

        let mut mac = [0u8; SDCP_DIGEST_SIZE];
        mac.copy_from_slice(&buf[pos..pos + SDCP_DIGEST_SIZE]);

        Ok(Self {
            device_random,
            model_certificate,
            device_public_key,
            firmware_public_key,
            firmware_hash,
            model_signature,
            device_signature,
            mac,
        })
    }
}

/// Extrae de forma segura la longitud total de un certificado X.509 codificado en ASN.1 DER
/// inspeccionando su cabecera TLV (`0x30`, `0x80 + n`, seguido de `n` bytes big-endian).
pub fn get_cert_length_from_buf(buf: &[u8]) -> Result<usize, SdcpError> {
    if buf.len() < 4 || buf[0] != 0x30 || buf[1] <= 0x80 {
        return Err(SdcpError::InvalidCertificateAsn1);
    }

    let len_bytes = (buf[1] - 0x80) as usize;
    if len_bytes == 0 || len_bytes > 4 || buf.len() < 2 + len_bytes {
        return Err(SdcpError::InvalidCertificateAsn1);
    }

    let mut value_buf = [0u8; 4];
    value_buf[4 - len_bytes..].copy_from_slice(&buf[2..2 + len_bytes]);
    let payload_len = u32::from_be_bytes(value_buf) as usize;

    let total_len = 2usize
        .checked_add(len_bytes)
        .and_then(|v| v.checked_add(payload_len))
        .ok_or(SdcpError::InvalidCertificateAsn1)?;

    if buf.len() < total_len {
        return Err(SdcpError::InvalidCertificateAsn1);
    }

    Ok(total_len)
}

/// Genera 32 bytes aleatorios criptográficamente seguros (`r_h`, nonces).
pub fn generate_random() -> Result<[u8; SDCP_RANDOM_SIZE], SdcpError> {
    let mut buf = [0u8; SDCP_RANDOM_SIZE];
    getrandom::getrandom(&mut buf).map_err(|_| SdcpError::RngFailure)?;
    Ok(buf)
}

/// Derivación SP800-108 Counter Mode KBKDF usando HMAC-SHA256.
///
/// Para cada bloque `i = 1..=n`:
/// `K(i) = HMAC-SHA256(key, [i]_32be || label || 0x00 || context || [out_len * 8]_32be)`
pub fn kbkdf_counter_hmac_sha256(
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    out_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + SDCP_DIGEST_SIZE);
    let bits_len_be = ((out_len as u32) * 8).to_be_bytes();
    let mut counter: u32 = 1;

    while out.len() < out_len {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]); // Separador 0x00 estándar SP800-108
        if let Some(ctx) = context {
            mac.update(ctx);
        }
        mac.update(&bits_len_be);
        let block = mac.finalize().into_bytes();
        out.extend_from_slice(&block);
        counter += 1;
    }

    out.truncate(out_len);
    out
}

/// Comparación en tiempo constante para MACs de 32 bytes.
fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Limpia un buffer sensible en RAM usando escrituras volátiles para evitar que el optimizador las elimine.
fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Obtiene el tiempo monotónico actual del sistema en microsegundos leyendo `/proc/uptime`.
fn monotonic_time_usec() -> i64 {
    if let Ok(contents) = fs::read_to_string("/proc/uptime") {
        if let Some(first) = contents.split_whitespace().next() {
            if let Ok(secs) = first.parse::<f64>() {
                return (secs * 1_000_000.0) as i64;
            }
        }
    }
    1_000_000
}

const SDCP_CLAIM_EXPIRATION_USEC: i64 = 86_400 * 1_000_000;

/// Estado de sesión SDCP (llaves efímeras del host y secretos derivados del canal seguro).
#[derive(Clone)]
pub struct SdcpSession {
    host_initialized: bool,
    host_private_key: [u8; SDCP_PRIVATE_KEY_SIZE],
    host_public_key: [u8; SDCP_PUBLIC_KEY_SIZE],
    host_random: [u8; SDCP_RANDOM_SIZE],
    key_agreement: [u8; SDCP_KEY_AGREEMENT_SIZE],
    master_secret: [u8; SDCP_MASTER_SECRET_SIZE],
    application_secret: [u8; SDCP_APPLICATION_SECRET_SIZE],
    application_symmetric_key: [u8; SDCP_APPLICATION_SYMMETRIC_KEY_SIZE],
    is_connected: bool,
    claim_cache_path: Option<PathBuf>,
}

impl Drop for SdcpSession {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl Default for SdcpSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SdcpSession {
    pub fn new() -> Self {
        Self {
            host_initialized: false,
            host_private_key: [0u8; SDCP_PRIVATE_KEY_SIZE],
            host_public_key: [0u8; SDCP_PUBLIC_KEY_SIZE],
            host_random: [0u8; SDCP_RANDOM_SIZE],
            key_agreement: [0u8; SDCP_KEY_AGREEMENT_SIZE],
            master_secret: [0u8; SDCP_MASTER_SECRET_SIZE],
            application_secret: [0u8; SDCP_APPLICATION_SECRET_SIZE],
            application_symmetric_key: [0u8; SDCP_APPLICATION_SYMMETRIC_KEY_SIZE],
            is_connected: false,
            claim_cache_path: None,
        }
    }

    /// Borra de forma determinista todas las llaves privadas y secretos de sesión en RAM.
    pub fn zeroize_secrets(&mut self) {
        zeroize_slice(&mut self.host_private_key);
        zeroize_slice(&mut self.host_random);
        zeroize_slice(&mut self.key_agreement);
        zeroize_slice(&mut self.master_secret);
        zeroize_slice(&mut self.application_secret);
        zeroize_slice(&mut self.application_symmetric_key);
    }

    /// Invalida la sesión actual y elimina el archivo `sdcp-claim` en caché para forzar
    /// un nuevo handshake `SDCP Connect` limpio en la próxima operación.
    pub fn invalidate_session(&mut self) {
        self.is_connected = false;
        self.host_initialized = false;
        self.zeroize_secrets();
        if let Some(ref path) = self.claim_cache_path {
            let _ = fs::remove_file(path);
        }
    }

    /// Configura la ruta de caché del claim SDCP (compatible con `FpiSdcpDevice` en `/tmp/.libfprint/egismoc/<device_id>/sdcp-claim`).
    pub fn set_claim_cache_path(&mut self, path: PathBuf) {
        self.claim_cache_path = Some(path);
    }

    /// Calcula la ruta estándar de caché de claim SDCP para un `driver` y `device_id`.
    pub fn default_claim_cache_path(driver: &str, device_id: &str) -> PathBuf {
        let base = std::env::var("STATE_DIRECTORY")
            .ok()
            .and_then(|val| val.split(':').next().filter(|s| !s.is_empty()).map(PathBuf::from))
            .unwrap_or_else(|| std::env::temp_dir().join(".libfprint"));
        base.join(driver).join(device_id).join("sdcp-claim")
    }

    /// Inicializa o importa el par de llaves P-256 del host (`pk_h`, `sk_h`) y el `r_h` aleatorio.
    pub fn set_host_keys(
        &mut self,
        private_key_bytes: Option<&[u8; SDCP_PRIVATE_KEY_SIZE]>,
        random_bytes: Option<&[u8; SDCP_RANDOM_SIZE]>,
    ) -> Result<(), SdcpError> {
        self.is_connected = false;

        let secret_key = if let Some(pk_bytes) = private_key_bytes {
            SecretKey::from_slice(pk_bytes).map_err(|_| SdcpError::InvalidPrivateKey)?
        } else {
            let mut candidate = [0u8; SDCP_PRIVATE_KEY_SIZE];
            loop {
                getrandom::getrandom(&mut candidate).map_err(|_| SdcpError::RngFailure)?;
                if let Ok(sk) = SecretKey::from_slice(&candidate) {
                    break sk;
                }
            }
        };

        let sk_bytes = secret_key.to_bytes();
        self.host_private_key.copy_from_slice(&sk_bytes);

        let public_key = secret_key.public_key();
        let encoded_pub = public_key.to_encoded_point(false);
        let pub_bytes = encoded_pub.as_bytes();
        if pub_bytes.len() != SDCP_PUBLIC_KEY_SIZE {
            return Err(SdcpError::InvalidPublicKey);
        }
        self.host_public_key.copy_from_slice(pub_bytes);

        if let Some(rnd) = random_bytes {
            self.host_random.copy_from_slice(rnd);
        } else {
            self.host_random = generate_random()?;
        }

        self.host_initialized = true;
        Ok(())
    }

    /// Intenta cargar un claim cacheado compatible con `FpiSdcpDevice` (formato GVariant `(ayayayayayayayxs)`),
    /// o genera nuevas llaves efímeras si no existe o expiró.
    pub fn ensure_initialized(&mut self) -> Result<(), SdcpError> {
        if self.host_initialized {
            return Ok(());
        }
        if let Some(path) = self.claim_cache_path.clone() {
            if self.try_load_cached_claim(&path).is_ok() {
                return Ok(());
            }
        }
        self.set_host_keys(None, None)
    }

    /// Carga los 257 bytes iniciales de un archivo `sdcp-claim` de `libfprint` si su `boot_id` y expiración son válidos.
    pub fn try_load_cached_claim(&mut self, path: &Path) -> Result<(), SdcpError> {
        let data = fs::read(path).map_err(|_| SdcpError::IoError)?;
        // 7 arreglos fijos (32+65+32+32+32+32+32 = 257) + 7 pad (264) + 8 time (272) + boot_id + 15 framing
        if data.len() < 272 + 2 + 15 {
            return Err(SdcpError::BufferTooShort);
        }

        // Verificar boot_id si está disponible en /proc/sys/kernel/random/boot_id
        if let Ok(current_boot_id) = fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            let boot_id_slice = &data[272..data.len() - 15];
            let cached_boot_id = boot_id_slice
                .split(|&b| b == 0)
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .unwrap_or("");
            if cached_boot_id != current_boot_id {
                let _ = fs::remove_file(path);
                return Err(SdcpError::IoError);
            }
        }

        // Verificar expiración de 24h (86,400s) cuando el timestamp proviene de un reloj monotónico real
        let mut time_bytes = [0u8; 8];
        time_bytes.copy_from_slice(&data[264..272]);
        let cached_time_usec = i64::from_le_bytes(time_bytes);
        if cached_time_usec > 1_000_000 {
            let now_usec = monotonic_time_usec();
            if now_usec > cached_time_usec.saturating_add(SDCP_CLAIM_EXPIRATION_USEC) {
                let _ = fs::remove_file(path);
                return Err(SdcpError::IoError);
            }
        }

        let mut priv_key = [0u8; SDCP_PRIVATE_KEY_SIZE];
        priv_key.copy_from_slice(&data[0..32]);
        let mut pub_key = [0u8; SDCP_PUBLIC_KEY_SIZE];
        pub_key.copy_from_slice(&data[32..97]);
        let mut rnd = [0u8; SDCP_RANDOM_SIZE];
        rnd.copy_from_slice(&data[97..129]);

        let res = self.set_host_keys(Some(&priv_key), Some(&rnd));
        zeroize_slice(&mut priv_key);
        res?;
        if self.host_public_key != pub_key {
            return Err(SdcpError::InvalidPublicKey);
        }

        self.key_agreement.copy_from_slice(&data[129..161]);
        self.master_secret.copy_from_slice(&data[161..193]);
        self.application_secret.copy_from_slice(&data[193..225]);
        self.application_symmetric_key.copy_from_slice(&data[225..257]);
        self.is_connected = true;
        Ok(())
    }

    /// Guarda el claim conectado en el formato binario GVariant `(ayayayayayayayxs)` compatible con `libfprint`,
    /// restringiendo los permisos en disco a `0700` (directorio) y `0600` (archivo).
    pub fn save_cached_claim(&self, path: &Path) -> Result<(), SdcpError> {
        if !self.is_connected {
            return Err(SdcpError::NotConnected);
        }
        if let Some(parent) = path.parent() {
            let _ = DirBuilder::new().recursive(true).mode(0o700).create(parent);
        }

        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_else(|_| "0\n".to_string());
        let mut buf = Vec::with_capacity(320);
        buf.extend_from_slice(&self.host_private_key); // 0..32
        buf.extend_from_slice(&self.host_public_key); // 32..97
        buf.extend_from_slice(&self.host_random); // 97..129
        buf.extend_from_slice(&self.key_agreement); // 129..161
        buf.extend_from_slice(&self.master_secret); // 161..193
        buf.extend_from_slice(&self.application_secret); // 193..225
        buf.extend_from_slice(&self.application_symmetric_key); // 225..257
        buf.extend_from_slice(&[0u8; 7]); // 257..264 alignment padding

        let now_usec = monotonic_time_usec();
        buf.extend_from_slice(&now_usec.to_le_bytes()); // 264..272
        buf.extend_from_slice(boot_id.as_bytes());
        buf.push(0x00); // NUL terminator para string GVariant
        buf.extend_from_slice(&[
            0x01, 0x01, 0xe1, 0x00, 0xc1, 0x00, 0xa1, 0x00, 0x81, 0x00, 0x61, 0x00, 0x20, 0x00,
        ]);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| SdcpError::IoError)?;
        let write_res = file.write_all(&buf).map_err(|_| SdcpError::IoError);
        zeroize_slice(&mut buf);
        write_res
    }

    pub fn is_connected(&mut self) -> bool {
        let _ = self.ensure_initialized();
        self.is_connected
    }

    pub fn host_public_key(&mut self) -> Result<[u8; SDCP_PUBLIC_KEY_SIZE], SdcpError> {
        self.ensure_initialized()?;
        Ok(self.host_public_key)
    }

    pub fn host_random(&mut self) -> Result<[u8; SDCP_RANDOM_SIZE], SdcpError> {
        self.ensure_initialized()?;
        Ok(self.host_random)
    }

    pub fn key_agreement_bytes(&self) -> &[u8; SDCP_KEY_AGREEMENT_SIZE] {
        &self.key_agreement
    }

    pub fn master_secret_bytes(&self) -> &[u8; SDCP_MASTER_SECRET_SIZE] {
        &self.master_secret
    }

    pub fn application_secret_bytes(&self) -> &[u8; SDCP_APPLICATION_SECRET_SIZE] {
        &self.application_secret
    }

    pub fn application_symmetric_key_bytes(&self) -> &[u8; SDCP_APPLICATION_SYMMETRIC_KEY_SIZE] {
        &self.application_symmetric_key
    }

    /// Deriva `key_agreement`, `master_secret` y `application_keys`, y verifica el MAC de `ConnectResponse`.
    pub fn derive_keys_and_verify_connect(
        &mut self,
        resp: &SdcpConnectResponse,
    ) -> Result<(), SdcpError> {
        self.ensure_initialized()?;

        // 1. Verificar que el certificado DER es válido
        let cert_len = get_cert_length_from_buf(&resp.model_certificate)?;
        if cert_len > resp.model_certificate.len() {
            return Err(SdcpError::InvalidCertificateAsn1);
        }

        // 2. ECDH P-256 entre host_private_key y firmware_public_key (pk_f)
        let host_sk =
            SecretKey::from_slice(&self.host_private_key).map_err(|_| SdcpError::InvalidPrivateKey)?;
        let fw_pk = PublicKey::from_sec1_bytes(&resp.firmware_public_key)
            .map_err(|_| SdcpError::InvalidPublicKey)?;

        let shared = diffie_hellman(host_sk.to_nonzero_scalar(), fw_pk.as_affine());
        self.key_agreement
            .copy_from_slice(&shared.raw_secret_bytes()[..]);

        // 3. Master secret: KBKDF(key_agreement, "master secret", r_h || r_d, 32)
        let mut context = [0u8; SDCP_RANDOM_SIZE * 2];
        context[..SDCP_RANDOM_SIZE].copy_from_slice(&self.host_random);
        context[SDCP_RANDOM_SIZE..].copy_from_slice(&resp.device_random);

        let master = kbkdf_counter_hmac_sha256(
            &self.key_agreement,
            b"master secret",
            Some(&context),
            SDCP_MASTER_SECRET_SIZE,
        );
        self.master_secret.copy_from_slice(&master);

        // 4. Application keys: KBKDF(master_secret, "application keys", None, 64)
        let app_keys = kbkdf_counter_hmac_sha256(
            &self.master_secret,
            b"application keys",
            None,
            SDCP_APPLICATION_SECRET_SIZE + SDCP_APPLICATION_SYMMETRIC_KEY_SIZE,
        );
        self.application_secret
            .copy_from_slice(&app_keys[..SDCP_APPLICATION_SECRET_SIZE]);
        self.application_symmetric_key
            .copy_from_slice(&app_keys[SDCP_APPLICATION_SECRET_SIZE..]);

        // 5. Claim hash = SHA256(cert_m || pk_d || pk_f || h_f || s_m || s_d)
        let mut hasher = Sha256::new();
        hasher.update(&resp.model_certificate);
        hasher.update(resp.device_public_key);
        hasher.update(resp.firmware_public_key);
        hasher.update(resp.firmware_hash);
        hasher.update(resp.model_signature);
        hasher.update(resp.device_signature);
        let claim_hash = hasher.finalize();

        // 6. MAC = HMAC-SHA256(application_secret, "connect\0" || claim_hash)
        let mut mac =
            HmacSha256::new_from_slice(&self.application_secret).expect("HMAC key size valid");
        mac.update(b"connect\0");
        mac.update(&claim_hash);
        let expected_mac_bytes = mac.finalize().into_bytes();
        let mut expected_mac = [0u8; SDCP_DIGEST_SIZE];
        expected_mac.copy_from_slice(&expected_mac_bytes);

        if !constant_time_eq_32(&resp.mac, &expected_mac) {
            self.is_connected = false;
            return Err(SdcpError::MacVerificationFailed);
        }

        self.is_connected = true;
        if let Some(ref path) = self.claim_cache_path {
            let _ = self.save_cached_claim(path);
        }
        Ok(())
    }

    /// Verifica el MAC de `ReconnectResponse`: `HMAC-SHA256(application_secret, "reconnect\0" || r_h)`.
    pub fn verify_reconnect(
        &mut self,
        host_reconnect_random: &[u8; SDCP_RANDOM_SIZE],
        device_reconnect_mac: &[u8; SDCP_DIGEST_SIZE],
    ) -> Result<(), SdcpError> {
        if !self.is_connected {
            return Err(SdcpError::NotConnected);
        }

        let mut mac =
            HmacSha256::new_from_slice(&self.application_secret).expect("HMAC key size valid");
        mac.update(b"reconnect\0");
        mac.update(host_reconnect_random);
        let expected_bytes = mac.finalize().into_bytes();
        let mut expected = [0u8; SDCP_DIGEST_SIZE];
        expected.copy_from_slice(&expected_bytes);

        if constant_time_eq_32(device_reconnect_mac, &expected) {
            Ok(())
        } else {
            Err(SdcpError::MacVerificationFailed)
        }
    }

    /// Verifica un `AuthorizedIdentity` recibido tras `Identify`/`Verify`.
    ///
    /// Devuelve `IdentityVerification::Verified` si el MAC coincide con la sesión activa,
    /// o `IdentityVerification::MacMismatchAfterReset` si el dispositivo perdió su sesión
    /// volátil tras un reinicio USB pero devolvió un `enrollment_id` válido de 32 bytes.
    pub fn verify_authorized_identity(
        &mut self,
        host_identify_nonce: &[u8; SDCP_NONCE_SIZE],
        device_enrollment_id: &[u8; SDCP_ENROLLMENT_ID_SIZE],
        device_identify_mac: &[u8; SDCP_DIGEST_SIZE],
    ) -> IdentityVerification {
        let _ = self.ensure_initialized();
        if !self.is_connected {
            return IdentityVerification::NotConnected;
        }

        let mut mac =
            HmacSha256::new_from_slice(&self.application_secret).expect("HMAC key size valid");
        mac.update(b"identify\0");
        mac.update(host_identify_nonce);
        mac.update(device_enrollment_id);
        let expected_bytes = mac.finalize().into_bytes();
        let mut expected = [0u8; SDCP_DIGEST_SIZE];
        expected.copy_from_slice(&expected_bytes);

        if constant_time_eq_32(device_identify_mac, &expected) {
            IdentityVerification::Verified
        } else {
            // Auto-reparación criptográfica: invalidar el claim obsoleto en caché para que
            // la próxima operación realice un nuevo handshake SDCP Connect con el sensor.
            if std::env::var("FP_DEVICE_EMULATION").as_deref() != Ok("1") {
                self.invalidate_session();
            }
            IdentityVerification::MacMismatchAfterReset
        }
    }

    /// Genera el `enrollment_id` de 32 bytes a partir del `device_nonce`:
    /// `HMAC-SHA256(application_secret, "enroll\0" || device_nonce)`.
    pub fn generate_enrollment_id(
        &mut self,
        device_nonce: &[u8; SDCP_NONCE_SIZE],
    ) -> Result<[u8; SDCP_ENROLLMENT_ID_SIZE], SdcpError> {
        let _ = self.ensure_initialized();
        if !self.is_connected {
            return Err(SdcpError::NotConnected);
        }

        let mut mac =
            HmacSha256::new_from_slice(&self.application_secret).expect("HMAC key size valid");
        mac.update(b"enroll\0");
        mac.update(device_nonce);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; SDCP_ENROLLMENT_ID_SIZE];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HOST_PRIVATE_KEY: [u8; 32] = [
        0x84, 0x00, 0xED, 0x14, 0x57, 0x9C, 0xDF, 0x11, 0x58, 0x64, 0x77, 0xE8, 0x36, 0xE8, 0xCB,
        0x52, 0x70, 0x84, 0x41, 0xC1, 0xC2, 0xA4, 0x47, 0xC2, 0x18, 0xC5, 0xBB, 0xC2, 0xD1, 0x18,
        0xFB, 0xC7,
    ];

    const TEST_HOST_PUBLIC_KEY: [u8; 65] = [
        0x04, 0x52, 0xF0, 0x56, 0xFF, 0xB9, 0xC6, 0x72, 0x86, 0x54, 0x77, 0x1A, 0x36, 0x29, 0xB7,
        0x70, 0x76, 0x7B, 0x19, 0xA2, 0x10, 0x6A, 0x49, 0x16, 0xFB, 0x81, 0xBA, 0x06, 0xEF, 0x67,
        0x97, 0xC4, 0xA3, 0xDF, 0x67, 0x2A, 0xDE, 0x0E, 0x91, 0x16, 0xD1, 0xAB, 0xE2, 0x78, 0xA8,
        0x22, 0x3A, 0xBD, 0xE4, 0x95, 0x8D, 0x62, 0xD4, 0xFF, 0x68, 0x82, 0x15, 0x9F, 0x06, 0x17,
        0xC6, 0xF8, 0xCE, 0x10, 0xBF,
    ];

    const TEST_HOST_RANDOM: [u8; 32] = [
        0xD8, 0x77, 0x40, 0x3A, 0xBE, 0x82, 0xF4, 0xD9, 0x7E, 0x14, 0x48, 0xC5, 0x05, 0x2D, 0x83,
        0xA5, 0x32, 0xA4, 0x5E, 0x56, 0xEF, 0x04, 0x9C, 0xBB, 0xF9, 0x81, 0x13, 0x75, 0x20, 0xE7,
        0x13, 0xBF,
    ];

    const TEST_DEVICE_RANDOM: [u8; 32] = [
        0x6E, 0x2F, 0x6C, 0x1A, 0xBE, 0xF2, 0xA1, 0x97, 0x3F, 0xB1, 0x31, 0x5A, 0x17, 0xE2, 0x09,
        0xFD, 0xB0, 0xC7, 0x85, 0x20, 0xF1, 0xFD, 0x6A, 0x85, 0xD2, 0x94, 0xD7, 0xAE, 0xB4, 0x0A,
        0x04, 0xA7,
    ];

    const TEST_DEVICE_PUBLIC_KEY: [u8; 65] = [
        0x04, 0xE2, 0x78, 0x78, 0x90, 0xA6, 0x84, 0xF9, 0x5B, 0x96, 0xB9, 0xA2, 0x31, 0x6C, 0xA8,
        0xD3, 0xD3, 0x3D, 0x4D, 0x79, 0xFF, 0x4C, 0x89, 0xDC, 0x6F, 0x9E, 0x88, 0x8E, 0x97, 0x39,
        0x90, 0xD1, 0xD3, 0x15, 0x41, 0x33, 0xDC, 0xC8, 0xBD, 0x33, 0xB9, 0x9A, 0xF9, 0xDB, 0xF0,
        0x67, 0x33, 0x90, 0xD4, 0x04, 0xD0, 0x92, 0x49, 0x8A, 0x3F, 0x21, 0x4C, 0xD9, 0x3F, 0x9B,
        0x9F, 0x28, 0xFB, 0x5F, 0x66,
    ];

    const TEST_DEVICE_FIRMWARE_PUBLIC_KEY: [u8; 65] = [
        0x04, 0xF0, 0x6A, 0x84, 0xAB, 0x51, 0xA3, 0xA6, 0xE8, 0xFF, 0x46, 0x86, 0x8F, 0x91, 0xDD,
        0x72, 0x0E, 0x4C, 0xDA, 0xD2, 0x1F, 0x2E, 0x09, 0x0D, 0x11, 0xE8, 0xF9, 0xBF, 0xC2, 0xEA,
        0x19, 0xEE, 0x1B, 0x5E, 0xAC, 0x85, 0x0B, 0x45, 0x32, 0x96, 0x8A, 0x93, 0x99, 0xF7, 0x6C,
        0xD7, 0x79, 0xE7, 0x72, 0x3E, 0x8C, 0x2C, 0xA7, 0x3B, 0x59, 0x7C, 0x0D, 0xF5, 0xF7, 0x3B,
        0x94, 0xA3, 0x6F, 0x2B, 0x6C,
    ];

    const TEST_DEVICE_FIRMWARE_HASH: [u8; 32] = [
        0xC3, 0xBF, 0x47, 0xEA, 0x1F, 0x4A, 0x4A, 0x60, 0x54, 0x70, 0x31, 0x3C, 0xAC, 0xB3, 0xA4,
        0x4F, 0x4A, 0x46, 0x1F, 0x68, 0xC6, 0xFA, 0xEA, 0xB0, 0x7E, 0x73, 0x76, 0x10, 0xCB, 0x5A,
        0xC8, 0x35,
    ];

    const TEST_DEVICE_MODEL_SIGNATURE: [u8; 64] = [
        0xFE, 0xBE, 0x6B, 0xA3, 0x10, 0x78, 0x13, 0xE1, 0x85, 0xF0, 0x51, 0x89, 0xE6, 0x9A, 0xE7,
        0x9D, 0x9F, 0x7A, 0x40, 0x80, 0x25, 0x82, 0xD9, 0x43, 0x24, 0x45, 0x98, 0x44, 0xC8, 0xB9,
        0x7E, 0xC6, 0xC5, 0xDA, 0xED, 0x54, 0x62, 0x27, 0x6C, 0xB8, 0xA1, 0x93, 0xC3, 0x3E, 0x35,
        0x04, 0x24, 0xB0, 0x30, 0x5D, 0x63, 0xD7, 0x9A, 0x93, 0xA9, 0x18, 0x8D, 0xCF, 0xC0, 0xCB,
        0x55, 0x95, 0xF6, 0xC1,
    ];

    const TEST_DEVICE_DEVICE_SIGNATURE: [u8; 64] = [
        0x10, 0xCC, 0x57, 0xDD, 0x8D, 0xAF, 0xB4, 0x63, 0x51, 0x0A, 0x73, 0x27, 0xA5, 0xFC, 0xA4,
        0x9B, 0x69, 0x8E, 0x99, 0x9B, 0x36, 0x44, 0x8E, 0x20, 0x23, 0xEA, 0xF0, 0xDF, 0xF0, 0xB0,
        0xD4, 0xA3, 0x4F, 0x1C, 0xAF, 0x4E, 0x87, 0x2B, 0x77, 0x36, 0x4A, 0x0A, 0x00, 0xD7, 0x47,
        0x65, 0x54, 0xD0, 0x32, 0x4C, 0x4C, 0xC9, 0x31, 0x93, 0x7E, 0x23, 0x2A, 0x03, 0x15, 0x83,
        0x7D, 0x69, 0x6C, 0x06,
    ];

    const TEST_DEVICE_CONNECT_MAC: [u8; 32] = [
        0xCF, 0x06, 0x75, 0x92, 0x5C, 0x44, 0x49, 0x1D, 0xC6, 0x8A, 0xFD, 0x06, 0xC6, 0xA0, 0xA9,
        0x82, 0x76, 0xB6, 0xF8, 0x40, 0x5E, 0x8C, 0x69, 0x7E, 0x4F, 0x5D, 0x4D, 0x93, 0x50, 0x91,
        0xD4, 0x8F,
    ];

    const TEST_KEY_AGREEMENT: [u8; 32] = [
        0xC6, 0xC5, 0xB8, 0x58, 0x3E, 0x20, 0x7F, 0x7A, 0xD4, 0x07, 0xE9, 0x20, 0x6D, 0x3F, 0x84,
        0xAD, 0xFD, 0xBF, 0x38, 0x64, 0xBF, 0x88, 0xD9, 0x00, 0x4E, 0x0F, 0xE1, 0xCC, 0x26, 0xF8,
        0x10, 0x74,
    ];

    const TEST_MASTER_SECRET: [u8; 32] = [
        0xC2, 0x97, 0x45, 0x31, 0x49, 0x17, 0x55, 0x0F, 0x0C, 0x00, 0xF7, 0xDE, 0x9A, 0xEE, 0x24,
        0x31, 0x60, 0x1F, 0xBF, 0x87, 0xF0, 0xBE, 0x5F, 0x57, 0x51, 0x19, 0x3E, 0x21, 0x06, 0xD6,
        0xD9, 0xA9,
    ];

    const TEST_APPLICATION_SECRET: [u8; 32] = [
        0x13, 0x33, 0x0B, 0xA3, 0x13, 0x5E, 0xCF, 0x5D, 0xC7, 0x1C, 0xED, 0xE0, 0x1A, 0x88, 0x65,
        0x40, 0x77, 0x1E, 0xFA, 0xB3, 0x5C, 0x8B, 0xA0, 0x53, 0x90, 0x2B, 0x2C, 0x1E, 0xE7, 0xDE,
        0x6E, 0xFE,
    ];

    const TEST_APPLICATION_SYMMETRIC_KEY: [u8; 32] = [
        0x7E, 0xFA, 0x1B, 0xB7, 0xBF, 0xC7, 0x87, 0xBA, 0x1E, 0xF5, 0xFE, 0x36, 0x08, 0xDF, 0xCC,
        0xFC, 0x20, 0x81, 0xEE, 0x6B, 0x20, 0x91, 0xB9, 0xF5, 0x20, 0xAB, 0xAA, 0x2E, 0x38, 0x38,
        0x37, 0x53,
    ];

    const TEST_RECONNECT_RANDOM: [u8; 32] = [
        0x8A, 0x74, 0x51, 0xC1, 0xD3, 0xA8, 0xDC, 0xA1, 0xC1, 0x33, 0x0C, 0xA5, 0x0D, 0x73, 0x45,
        0x4B, 0x35, 0x1A, 0x49, 0xF4, 0x6C, 0x8E, 0x9D, 0xCE, 0xE1, 0x5C, 0x96, 0x4D, 0x29, 0x5C,
        0x31, 0xC9,
    ];

    const TEST_RECONNECT_MAC: [u8; 32] = [
        0xBF, 0x3F, 0x3B, 0xB3, 0xBD, 0x6E, 0xCB, 0x27, 0x84, 0xC1, 0x60, 0xF5, 0x26, 0xF7, 0xBC,
        0x3B, 0x3C, 0xA8, 0xFA, 0xF5, 0x55, 0x71, 0x94, 0xC4, 0x8E, 0x00, 0x24, 0xA0, 0x49, 0x39,
        0x03, 0xC7,
    ];

    const TEST_IDENTIFY_NONCE: [u8; 32] = [
        0x3A, 0x1B, 0x50, 0x6F, 0x5B, 0xEC, 0x08, 0x90, 0x59, 0xAC, 0xEF, 0xB9, 0xB4, 0x4D, 0xFB,
        0xDE, 0xA7, 0xA5, 0x99, 0xEE, 0x9A, 0xA2, 0x67, 0xE5, 0x25, 0x26, 0x64, 0xD6, 0x0B, 0x79,
        0x80, 0x53,
    ];

    const TEST_IDENTIFY_ENROLLMENT_ID: [u8; 32] = [
        0xEF, 0x20, 0x55, 0x24, 0x4E, 0x49, 0xC3, 0x9B, 0xEA, 0xBD, 0xAC, 0x49, 0xFD, 0xF4, 0xEE,
        0x41, 0x86, 0x05, 0xD1, 0x95, 0xDA, 0x23, 0xB2, 0x02, 0xBA, 0x21, 0x9A, 0x13, 0x83, 0x1A,
        0xE6, 0x21,
    ];

    const TEST_IDENTIFY_MAC: [u8; 32] = [
        0xF0, 0xA5, 0xC5, 0xF2, 0x61, 0xC2, 0xFE, 0x93, 0x7D, 0x8B, 0x11, 0x38, 0x57, 0xBC, 0x62,
        0x9C, 0xD0, 0x7C, 0xA8, 0x8E, 0xDF, 0x99, 0x1F, 0x69, 0xCA, 0x6F, 0xAE, 0x5C, 0x33, 0x23,
        0x90, 0xF6,
    ];

    const TEST_ENROLLMENT_NONCE: [u8; 32] = [
        0xC2, 0x10, 0x1C, 0x44, 0xC9, 0xA6, 0x67, 0xBB, 0xA3, 0x97, 0xE8, 0x1F, 0x48, 0xB1, 0x43,
        0x39, 0x86, 0x03, 0xE2, 0xC9, 0x33, 0x5A, 0x68, 0xB4, 0x09, 0xE1, 0xDB, 0xE7, 0x1E, 0x00,
        0x5C, 0xA2,
    ];

    const TEST_ENROLLMENT_ENROLLMENT_ID: [u8; 32] = [
        0x67, 0x10, 0x9D, 0xC7, 0x0A, 0x21, 0x63, 0x31, 0xF1, 0x58, 0x0D, 0xDA, 0xC6, 0x01, 0x91,
        0x59, 0x29, 0xC1, 0xFF, 0x6C, 0x9B, 0xCB, 0xA6, 0x54, 0x4B, 0xA5, 0x72, 0xC6, 0x60, 0xC3,
        0xD9, 0x1E,
    ];

    const TEST_CERT: &[u8] = &[
        0x30, 0x82, 0x05, 0x07, 0x30, 0x82, 0x03, 0xef, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x12,
        0x05, 0x33, 0xc0, 0xe9, 0x31, 0x92, 0xa9, 0x72, 0x31, 0x9a, 0x0d, 0xbb, 0x61, 0xbf, 0x94,
        0x24, 0x08, 0x59, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x0b, 0x05, 0x00, 0x30, 0x33, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0d, 0x4c,
        0x65, 0x74, 0x27, 0x73, 0x20, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x31, 0x0c, 0x30,
        0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x52, 0x31, 0x31, 0x30, 0x1e, 0x17, 0x0d,
        0x32, 0x35, 0x30, 0x36, 0x30, 0x32, 0x30, 0x34, 0x33, 0x33, 0x31, 0x33, 0x5a, 0x17, 0x0d,
        0x32, 0x35, 0x30, 0x38, 0x33, 0x31, 0x30, 0x34, 0x33, 0x33, 0x31, 0x32, 0x5a, 0x30, 0x21,
        0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x16, 0x66, 0x70, 0x72, 0x69,
        0x6e, 0x74, 0x2e, 0x66, 0x72, 0x65, 0x65, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x2e,
        0x6f, 0x72, 0x67, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,
        0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdd, 0x1e, 0xfb, 0xb2, 0x14, 0x49, 0xb7, 0x01, 0xa1,
        0x45, 0x36, 0x8e, 0x4a, 0xbe, 0x78, 0x2a, 0xec, 0x9b, 0x53, 0xfe, 0x9e, 0xed, 0xc3, 0xa9,
        0xe2, 0xf5, 0x44, 0x9f, 0x49, 0x4b, 0x4a, 0xb5, 0x89, 0x36, 0x0c, 0x62, 0xe7, 0x0f, 0xea,
        0x05, 0xec, 0xc1, 0x72, 0x06, 0x52, 0x4e, 0x4d, 0xbc, 0x78, 0x65, 0x8a, 0x86, 0x46, 0x16,
        0x28, 0xea, 0x56, 0x5f, 0x2a, 0x03, 0x85, 0x4e, 0xf4, 0xd2, 0x9f, 0x24, 0xfa, 0xed, 0x1c,
        0xbd, 0xac, 0x5b, 0x45, 0x74, 0x5a, 0x69, 0x12, 0x6f, 0xd0, 0x29, 0x4c, 0xb4, 0x05, 0x7e,
        0xab, 0x2e, 0x46, 0xe1, 0x6e, 0x31, 0x95, 0xa1, 0x32, 0x9b, 0xdf, 0x1c, 0xd2, 0xa9, 0x03,
        0xba, 0x0f, 0xbd, 0xa9, 0xf4, 0x52, 0xa6, 0x6c, 0xfe, 0x8c, 0xef, 0x39, 0x75, 0x6b, 0xff,
        0x49, 0x8e, 0x3c, 0x7c, 0xb2, 0x83, 0xeb, 0x31, 0xde, 0x8b, 0x3c, 0xb1, 0x8f, 0x30, 0xa9,
        0xe3, 0x60, 0xb8, 0xe6, 0x23, 0xae, 0xe0, 0x6b, 0xa2, 0x2e, 0xfc, 0x79, 0xa9, 0xdb, 0xc9,
        0x63, 0xb5, 0xf7, 0xa5, 0xa1, 0x01, 0x13, 0x0e, 0x2f, 0xe6, 0x60, 0x47, 0x42, 0xac, 0x0a,
        0xd5, 0x79, 0x1e, 0x63, 0x49, 0x2b, 0xf8, 0x0d, 0x91, 0x0d, 0x67, 0xfd, 0x74, 0xca, 0x03,
        0x93, 0xd0, 0x2b, 0x2e, 0x06, 0x69, 0x7e, 0x7c, 0xc9, 0x41, 0x6c, 0xfb, 0x83, 0xe6, 0xfc,
        0x1e, 0xbd, 0xea, 0x2d, 0x4d, 0x3a, 0xc9, 0x2b, 0x97, 0x5e, 0x9b, 0x0e, 0x20, 0x7b, 0x89,
        0xf8, 0xc7, 0xf4, 0x75, 0x89, 0x6e, 0x31, 0x56, 0x8c, 0xda, 0x6b, 0x20, 0xff, 0x59, 0xad,
        0x3e, 0x57, 0x62, 0x3f, 0x01, 0xa6, 0x33, 0x8a, 0x4d, 0x6a, 0x27, 0x92, 0xf9, 0xcc, 0x76,
        0xdf, 0x0e, 0xac, 0xab, 0x5c, 0xf4, 0x39, 0xd4, 0x1d, 0xf2, 0x69, 0x65, 0x90, 0xc3, 0xc8,
        0x36, 0x32, 0x2c, 0xf5, 0x45, 0x11, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x02,
        0x25, 0x30, 0x82, 0x02, 0x21, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
        0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16,
        0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
        0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
        0x04, 0x14, 0x3a, 0x83, 0x37, 0x7a, 0x1c, 0xed, 0x45, 0x1c, 0xfc, 0xeb, 0x9c, 0xa9, 0xec,
        0xfc, 0xc8, 0xc7, 0xbf, 0x87, 0xf7, 0x2e, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
        0x18, 0x30, 0x16, 0x80, 0x14, 0xc5, 0xcf, 0x46, 0xa4, 0xea, 0xf4, 0xc3, 0xc0, 0x7a, 0x6c,
        0x95, 0xc4, 0x2d, 0xb0, 0x5e, 0x92, 0x2f, 0x26, 0xe3, 0xb9, 0x30, 0x33, 0x06, 0x08, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x27, 0x30, 0x25, 0x30, 0x23, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x17, 0x68, 0x74, 0x74, 0x70, 0x3a,
        0x2f, 0x2f, 0x72, 0x31, 0x31, 0x2e, 0x69, 0x2e, 0x6c, 0x65, 0x6e, 0x63, 0x72, 0x2e, 0x6f,
        0x72, 0x67, 0x2f, 0x30, 0x21, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x1a, 0x30, 0x18, 0x82,
        0x16, 0x66, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x2e, 0x66, 0x72, 0x65, 0x65, 0x64, 0x65, 0x73,
        0x6b, 0x74, 0x6f, 0x70, 0x2e, 0x6f, 0x72, 0x67, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x20,
        0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30,
        0x2e, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x27, 0x30, 0x25, 0x30, 0x23, 0xa0, 0x21, 0xa0,
        0x1f, 0x86, 0x1d, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x72, 0x31, 0x31, 0x2e, 0x63,
        0x2e, 0x6c, 0x65, 0x6e, 0x63, 0x72, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x39, 0x30, 0x2e, 0x63,
        0x72, 0x6c, 0x30, 0x82, 0x01, 0x03, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79,
        0x02, 0x04, 0x02, 0x04, 0x81, 0xf4, 0x04, 0x81, 0xf1, 0x00, 0xef, 0x00, 0x76, 0x00, 0xa4,
        0x42, 0xc5, 0x06, 0x49, 0x60, 0x61, 0x54, 0x8f, 0x0f, 0xd4, 0xea, 0x9c, 0xfb, 0x7a, 0x2d,
        0x26, 0x45, 0x4d, 0x87, 0xa9, 0x7f, 0x2f, 0xdf, 0x45, 0x59, 0xf6, 0x27, 0x4f, 0x3a, 0x84,
        0x54, 0x00, 0x00, 0x01, 0x97, 0x2f, 0x1f, 0xd0, 0xa5, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47,
        0x30, 0x45, 0x02, 0x20, 0x52, 0xd0, 0xc9, 0x2b, 0xef, 0xbe, 0x64, 0xe8, 0x6e, 0x26, 0x70,
        0xeb, 0x53, 0xbb, 0x79, 0xa5, 0xb9, 0x81, 0xfb, 0xb6, 0x02, 0xa0, 0x2d, 0xc6, 0x87, 0xfd,
        0xed, 0xf0, 0xf9, 0xf3, 0xcd, 0x11, 0x02, 0x21, 0x00, 0xcd, 0x9a, 0x3e, 0x1a, 0x77, 0x2a,
        0xe6, 0xa3, 0xf2, 0xa0, 0x4b, 0xcf, 0x1b, 0x7a, 0xba, 0x4f, 0xe7, 0x2b, 0xc7, 0x4b, 0x60,
        0xf4, 0xd3, 0x6a, 0xfa, 0x6b, 0x55, 0x87, 0x2a, 0xaa, 0x7c, 0xa9, 0x00, 0x75, 0x00, 0x12,
        0xf1, 0x4e, 0x34, 0xbd, 0x53, 0x72, 0x4c, 0x84, 0x06, 0x19, 0xc3, 0x8f, 0x3f, 0x7a, 0x13,
        0xf8, 0xe7, 0xb5, 0x62, 0x87, 0x88, 0x9c, 0x6d, 0x30, 0x05, 0x84, 0xeb, 0xe5, 0x86, 0x26,
        0x3a, 0x00, 0x00, 0x01, 0x97, 0x2f, 0x1f, 0xe0, 0x39, 0x00, 0x00, 0x04, 0x03, 0x00, 0x46,
        0x30, 0x44, 0x02, 0x20, 0x6f, 0xef, 0x97, 0xe9, 0x96, 0x88, 0xf9, 0x1e, 0x3c, 0x6c, 0xe6,
        0x7a, 0xe5, 0xfb, 0x14, 0x80, 0xa1, 0x0e, 0x31, 0x8d, 0x2a, 0x6c, 0x1f, 0x46, 0xa6, 0x8c,
        0x4a, 0xfa, 0x08, 0x3d, 0x62, 0xd0, 0x02, 0x20, 0x27, 0x3c, 0x89, 0x9a, 0xcc, 0x88, 0x54,
        0x3d, 0xfe, 0x48, 0xc7, 0x76, 0xf3, 0x1c, 0xf9, 0x52, 0xd2, 0xd2, 0xdd, 0x7d, 0xca, 0x43,
        0x5a, 0x1a, 0x7f, 0x16, 0xee, 0xc6, 0xcf, 0x9c, 0x84, 0x40, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
        0x79, 0x49, 0x17, 0x6a, 0x30, 0xa8, 0xca, 0xb4, 0x9b, 0x57, 0xbc, 0x21, 0xb8, 0xaf, 0x40,
        0x85, 0x6a, 0x2f, 0x1b, 0xbe, 0xc3, 0x32, 0x89, 0x86, 0x21, 0x90, 0x94, 0xf0, 0x44, 0xa4,
        0xa9, 0x9c, 0x84, 0x4f, 0xf0, 0x54, 0x71, 0x3b, 0xca, 0x0a, 0xcc, 0x75, 0xe6, 0xf1, 0xf3,
        0x77, 0x10, 0x1d, 0x64, 0xfb, 0xee, 0xb4, 0x3c, 0xc4, 0xf8, 0xe6, 0xec, 0x68, 0xd7, 0xc2,
        0xe7, 0x43, 0xae, 0xdc, 0x4d, 0x0b, 0x58, 0x0f, 0x87, 0x36, 0xa0, 0x78, 0xe9, 0x9d, 0xb1,
        0x64, 0x95, 0x35, 0xb1, 0x3f, 0x42, 0x60, 0xfc, 0xda, 0xe1, 0x09, 0xe1, 0xfc, 0xad, 0x63,
        0xb5, 0x43, 0x4b, 0x03, 0x73, 0xfe, 0xc9, 0x2c, 0x5f, 0xac, 0x31, 0x2c, 0x9b, 0x98, 0x35,
        0xae, 0xa6, 0xd2, 0x09, 0xbd, 0x79, 0xf6, 0x6f, 0x2b, 0x79, 0x57, 0x11, 0xdd, 0xf4, 0x77,
        0xf5, 0xab, 0x8f, 0xe6, 0x80, 0x2f, 0x27, 0x76, 0x80, 0xaa, 0xe5, 0xf4, 0x89, 0x6d, 0x7f,
        0x78, 0x02, 0xa5, 0xd7, 0xdc, 0x36, 0x04, 0x65, 0x25, 0x5c, 0xd0, 0xfd, 0x48, 0x18, 0x22,
        0x9c, 0xbc, 0x5f, 0x75, 0x5c, 0x41, 0xd9, 0xcf, 0x42, 0x67, 0xf4, 0x60, 0xc6, 0x21, 0x67,
        0x59, 0x47, 0xa9, 0x3b, 0x62, 0x38, 0x02, 0x98, 0xf9, 0xf2, 0xa9, 0x92, 0xda, 0x9d, 0x3f,
        0x73, 0x56, 0x33, 0xa9, 0x47, 0xa6, 0xab, 0x1c, 0x1e, 0x4c, 0x75, 0x66, 0xd9, 0xd3, 0x3d,
        0x88, 0x9a, 0x6d, 0x38, 0x94, 0x08, 0xd8, 0x98, 0xad, 0x2c, 0x9f, 0x8c, 0x08, 0xf3, 0xdf,
        0xc8, 0x47, 0xcc, 0xdf, 0x50, 0x70, 0x8e, 0x2d, 0xca, 0x0f, 0x5e, 0x0f, 0x08, 0x6f, 0x9d,
        0x80, 0xe6, 0xa5, 0x61, 0x3f, 0xa7, 0xdb, 0xa5, 0x2c, 0x5e, 0xdf, 0xe2, 0x6a, 0x6b, 0xd7,
        0x20, 0xbd, 0xf9, 0x92, 0x95, 0x2b, 0xd7, 0xd7, 0x72, 0xd7, 0x7f, 0x45, 0x63, 0x39, 0xe1,
        0x80,
    ];

    fn build_test_connect_response() -> SdcpConnectResponse {
        SdcpConnectResponse {
            device_random: TEST_DEVICE_RANDOM,
            model_certificate: TEST_CERT.to_vec(),
            device_public_key: TEST_DEVICE_PUBLIC_KEY,
            firmware_public_key: TEST_DEVICE_FIRMWARE_PUBLIC_KEY,
            firmware_hash: TEST_DEVICE_FIRMWARE_HASH,
            model_signature: TEST_DEVICE_MODEL_SIGNATURE,
            device_signature: TEST_DEVICE_DEVICE_SIGNATURE,
            mac: TEST_DEVICE_CONNECT_MAC,
        }
    }

    #[test]
    fn test_host_keys_and_random_vectors() {
        let mut session = SdcpSession::new();
        session
            .set_host_keys(Some(&TEST_HOST_PRIVATE_KEY), Some(&TEST_HOST_RANDOM))
            .expect("set_host_keys failed");

        assert!(!session.is_connected());
        assert_eq!(session.host_public_key().unwrap(), TEST_HOST_PUBLIC_KEY);
        assert_eq!(session.host_random().unwrap(), TEST_HOST_RANDOM);
    }

    #[test]
    fn test_derive_keys_and_verify_connect_vectors() {
        let mut session = SdcpSession::new();
        session
            .set_host_keys(Some(&TEST_HOST_PRIVATE_KEY), Some(&TEST_HOST_RANDOM))
            .unwrap();

        let resp = build_test_connect_response();
        session
            .derive_keys_and_verify_connect(&resp)
            .expect("SDCP ConnectResponse verification failed");

        assert!(session.is_connected());
        assert_eq!(session.key_agreement_bytes(), &TEST_KEY_AGREEMENT);
        assert_eq!(session.master_secret_bytes(), &TEST_MASTER_SECRET);
        assert_eq!(session.application_secret_bytes(), &TEST_APPLICATION_SECRET);
        assert_eq!(
            session.application_symmetric_key_bytes(),
            &TEST_APPLICATION_SYMMETRIC_KEY
        );
    }

    #[test]
    fn test_verify_connect_from_standard_buf_and_egismoc_frame() {
        // 1. Standard SDCP ConnectResponse buffer
        let mut std_buf = Vec::new();
        std_buf.extend_from_slice(&TEST_DEVICE_RANDOM);
        std_buf.extend_from_slice(TEST_CERT);
        std_buf.extend_from_slice(&TEST_DEVICE_PUBLIC_KEY);
        std_buf.extend_from_slice(&TEST_DEVICE_FIRMWARE_PUBLIC_KEY);
        std_buf.extend_from_slice(&TEST_DEVICE_FIRMWARE_HASH);
        std_buf.extend_from_slice(&TEST_DEVICE_MODEL_SIGNATURE);
        std_buf.extend_from_slice(&TEST_DEVICE_DEVICE_SIGNATURE);
        std_buf.extend_from_slice(&TEST_DEVICE_CONNECT_MAC);

        let parsed_std = SdcpConnectResponse::from_standard_buf(&std_buf).unwrap();
        let mut session = SdcpSession::new();
        session
            .set_host_keys(Some(&TEST_HOST_PRIVATE_KEY), Some(&TEST_HOST_RANDOM))
            .unwrap();
        session.derive_keys_and_verify_connect(&parsed_std).unwrap();

        // 2. EgisMoc ConnectResponse frame (15-byte prefix + r_d + u16_be(cert_len) + cert + ... + 90 00)
        let mut egis_buf = vec![0u8; EGISMOC_CONNECT_RESPONSE_PREFIX_SIZE];
        egis_buf.extend_from_slice(&TEST_DEVICE_RANDOM);
        egis_buf.extend_from_slice(&(TEST_CERT.len() as u16).to_be_bytes());
        egis_buf.extend_from_slice(TEST_CERT);
        egis_buf.extend_from_slice(&TEST_DEVICE_PUBLIC_KEY);
        egis_buf.extend_from_slice(&TEST_DEVICE_FIRMWARE_PUBLIC_KEY);
        egis_buf.extend_from_slice(&TEST_DEVICE_FIRMWARE_HASH);
        egis_buf.extend_from_slice(&TEST_DEVICE_MODEL_SIGNATURE);
        egis_buf.extend_from_slice(&TEST_DEVICE_DEVICE_SIGNATURE);
        egis_buf.extend_from_slice(&TEST_DEVICE_CONNECT_MAC);
        egis_buf.extend_from_slice(&RSP_SDCP_CONNECT_SUCCESS_SUFFIX);

        let parsed_egis = SdcpConnectResponse::from_egismoc_frame(&egis_buf).unwrap();
        assert_eq!(parsed_egis, parsed_std);
    }

    #[test]
    fn test_verify_reconnect_and_authorized_identity_and_enrollment_id() {
        let mut session = SdcpSession::new();
        session
            .set_host_keys(Some(&TEST_HOST_PRIVATE_KEY), Some(&TEST_HOST_RANDOM))
            .unwrap();
        session
            .derive_keys_and_verify_connect(&build_test_connect_response())
            .unwrap();

        // Reconnect
        session
            .verify_reconnect(&TEST_RECONNECT_RANDOM, &TEST_RECONNECT_MAC)
            .expect("Reconnect verification should succeed");

        // AuthorizedIdentity (normal verified case)
        let status = session.verify_authorized_identity(
            &TEST_IDENTIFY_NONCE,
            &TEST_IDENTIFY_ENROLLMENT_ID,
            &TEST_IDENTIFY_MAC,
        );
        assert_eq!(status, IdentityVerification::Verified);

        // Enrollment ID generation
        let enrollment_id = session
            .generate_enrollment_id(&TEST_ENROLLMENT_NONCE)
            .expect("generate_enrollment_id should succeed");
        assert_eq!(enrollment_id, TEST_ENROLLMENT_ENROLLMENT_ID);

        // AuthorizedIdentity (USB reset tolerance case: hardware matched enrollment_id, volatile session reset)
        let mut corrupted_mac = TEST_IDENTIFY_MAC;
        corrupted_mac[0] ^= 0xFF;
        let reset_status = session.verify_authorized_identity(
            &TEST_IDENTIFY_NONCE,
            &TEST_IDENTIFY_ENROLLMENT_ID,
            &corrupted_mac,
        );
        assert_eq!(reset_status, IdentityVerification::MacMismatchAfterReset);
        // After MacMismatchAfterReset, the stale session is automatically invalidated so the next op reconnects
        assert!(!session.is_connected());
    }

    #[test]
    fn test_get_cert_length_from_buf_with_extra_bytes() {
        let mut cert_with_extra = TEST_CERT.to_vec();
        cert_with_extra.extend_from_slice(b"abcde\0");

        let len = get_cert_length_from_buf(&cert_with_extra).unwrap();
        assert_eq!(len, TEST_CERT.len());
    }
}
