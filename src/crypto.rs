//! Cryptographic primitives: mmap/mlock RAM-pinned keys, HKDF-SHA512 envelope wrapping,
//! KEK unseal-key rotation, AES-256-GCM AEAD with Associated Data (AAD), strict TLS 1.3
//! server configuration, and SHA-512 constant-time token hashing.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_AAD: &[u8] = b"sovereign-vault:v2:envelope";
const KEK_INFO: &[u8] = b"sovereign-vault:v2:kek";
const SQLCIPHER_KEY_INFO: &[u8] = b"sovereign-vault:v2:sqlcipher-db-key";
const VALUE_AEAD_KEY_INFO: &[u8] = b"sovereign-vault:v2:value-aead-key";
const AUDIT_CHAIN_KEY_INFO: &[u8] = b"sovereign-vault:v2:audit-chain-key";

/// Precomputed SHA-512 hex digest of `[0u8; 32]` used to equalize work when a `token_id` lookup misses.
pub const DUMMY_TOKEN_HASH_SHA512_HEX: &str =
    "50f685a26f7141114585c01332262597101f9860d233c703237d8c22923c4a269a0d23f35852f71c80f875e2b0d84b170565c121318a93f94f0b7f980d612432";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid or corrupt unseal key")]
    InvalidUnsealKey,
    #[error("Envelope header corrupt or unsupported")]
    CorruptEnvelope,
    #[error("AEAD cryptographic operation failed")]
    AeadFailure,
    #[error("Memory allocation failure for locked key page")]
    MemoryAllocationFailed,
}

/// Non-secret envelope metadata persisted to `/data/vault.envelope` (`0600`).
/// Contains zero plaintext key material; unwrapping requires the external 256-bit unseal key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub version: u32,
    pub kdf: String,
    pub kdf_salt_hex: String,
    pub dek_nonce_hex: String,
    pub wrapped_dek_hex: String,
}

/// A 256-bit cryptographic key stored in a dedicated, page-aligned anonymous `mmap` region
/// pinned in physical RAM via `mlock()`, excluded from core dumps via `MADV_DONTDUMP`,
/// and scrubbed with volatile zeroization prior to `munlock()` + `munmap()` on drop.
pub struct LockedKey {
    #[cfg(unix)]
    ptr: *mut u8,
    #[cfg(unix)]
    alloc_len: usize,
    #[cfg(unix)]
    is_mlocked: bool,
    #[cfg(not(unix))]
    fallback: Box<[u8; 32]>,
}

// SAFETY: `LockedKey` exclusively owns its private anonymous `mmap` allocation and
// only exposes immutable `&[u8; 32]` reads after construction until `Drop`.
unsafe impl Send for LockedKey {}
unsafe impl Sync for LockedKey {}

impl LockedKey {
    /// Move 32 key bytes into a dedicated RAM-locked page and zeroize the caller's buffer in place.
    pub fn new(mut raw_bytes: [u8; 32]) -> Result<Self, CryptoError> {
        Self::from_mut_array(&mut raw_bytes)
    }

    /// Move 32 key bytes from a mutable reference into a dedicated RAM-locked page,
    /// scrubbing the caller's stack/heap buffer in place without unzeroized by-value stack copies.
    pub fn from_mut_array(raw_bytes: &mut [u8; 32]) -> Result<Self, CryptoError> {
        #[cfg(unix)]
        unsafe {
            let page_size = {
                let sz = libc::sysconf(libc::_SC_PAGESIZE);
                if sz <= 0 {
                    4096usize
                } else {
                    sz as usize
                }
            };
            let alloc_len = page_size.max(32);

            let map_ptr = libc::mmap(
                std::ptr::null_mut(),
                alloc_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if map_ptr == libc::MAP_FAILED || map_ptr.is_null() {
                raw_bytes.zeroize();
                return Err(CryptoError::MemoryAllocationFailed);
            }

            let byte_ptr = map_ptr as *mut u8;
            std::ptr::copy_nonoverlapping(raw_bytes.as_ptr(), byte_ptr, 32);
            raw_bytes.zeroize();

            #[cfg(target_os = "linux")]
            {
                let _ = libc::madvise(map_ptr, alloc_len, libc::MADV_DONTDUMP);
                let _ = libc::madvise(map_ptr, alloc_len, libc::MADV_WIPEONFORK);
            }

            let is_mlocked = libc::mlock(map_ptr, alloc_len) == 0;
            if !is_mlocked {
                tracing::warn!(
                    "mlock() returned non-zero (grant CAP_IPC_LOCK and check ulimits.memlock); zeroize-on-drop remains active"
                );
            }

            let _ = libc::mprotect(map_ptr, alloc_len, libc::PROT_READ);

            Ok(Self {
                ptr: byte_ptr,
                alloc_len,
                is_mlocked,
            })
        }

        #[cfg(not(unix))]
        {
            let mut boxed = Box::new([0u8; 32]);
            boxed.copy_from_slice(raw_bytes);
            raw_bytes.zeroize();
            Ok(Self { fallback: boxed })
        }
    }

    /// Borrow the 32-byte key slice in place without copying onto the stack.
    pub fn as_bytes(&self) -> &[u8; 32] {
        #[cfg(unix)]
        unsafe {
            &*(self.ptr as *const [u8; 32])
        }
        #[cfg(not(unix))]
        {
            &self.fallback
        }
    }

    /// Report whether the OS kernel accepted `mlock()` pinning for this key page.
    pub fn is_memory_locked(&self) -> bool {
        #[cfg(unix)]
        {
            self.is_mlocked
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = libc::mprotect(
                self.ptr as *mut libc::c_void,
                self.alloc_len,
                libc::PROT_READ | libc::PROT_WRITE,
            );
            let slice = std::slice::from_raw_parts_mut(self.ptr, self.alloc_len);
            slice.zeroize();
            if self.is_mlocked {
                let _ = libc::munlock(self.ptr as *const libc::c_void, self.alloc_len);
            }
            let _ = libc::munmap(self.ptr as *mut libc::c_void, self.alloc_len);
        }
        #[cfg(not(unix))]
        {
            self.fallback.zeroize();
        }
    }
}

/// Generate a fresh 256-bit random unseal key (`Zeroizing<[u8; 32]>`).
pub fn generate_unseal_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(key.as_mut());
    key
}

fn wrap_master_dek_with_unseal_key(
    unseal_key: &[u8; 32],
    master_dek: &[u8; 32],
) -> Result<EnvelopeHeader, CryptoError> {
    let mut kdf_salt = Zeroizing::new([0u8; 32]);
    let mut dek_nonce = Zeroizing::new([0u8; 12]);
    rand::thread_rng().fill_bytes(kdf_salt.as_mut());
    rand::thread_rng().fill_bytes(dek_nonce.as_mut());

    let mut kek = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha512>::new(Some(kdf_salt.as_ref()), unseal_key);
    hk.expand(KEK_INFO, kek.as_mut())
        .map_err(|_| CryptoError::AeadFailure)?;

    let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| CryptoError::AeadFailure)?;
    let wrapped_dek = Zeroizing::new(
        cipher
            .encrypt(
                Nonce::from_slice(dek_nonce.as_ref()),
                Payload {
                    msg: master_dek,
                    aad: ENVELOPE_AAD,
                },
            )
            .map_err(|_| CryptoError::AeadFailure)?,
    );

    Ok(EnvelopeHeader {
        version: 2,
        kdf: "hkdf-sha512".to_string(),
        kdf_salt_hex: hex_encode(kdf_salt.as_ref()),
        dek_nonce_hex: hex_encode(dek_nonce.as_ref()),
        wrapped_dek_hex: hex_encode(wrapped_dek.as_slice()),
    })
}

fn unwrap_raw_master_dek(
    unseal_key: &[u8; 32],
    header: &EnvelopeHeader,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if header.version != 2 || header.kdf != "hkdf-sha512" {
        return Err(CryptoError::CorruptEnvelope);
    }

    let kdf_salt =
        Zeroizing::new(hex_decode(&header.kdf_salt_hex).map_err(|_| CryptoError::CorruptEnvelope)?);
    let dek_nonce = Zeroizing::new(
        hex_decode(&header.dek_nonce_hex).map_err(|_| CryptoError::CorruptEnvelope)?,
    );
    let wrapped_dek = Zeroizing::new(
        hex_decode(&header.wrapped_dek_hex).map_err(|_| CryptoError::CorruptEnvelope)?,
    );

    if kdf_salt.len() != 32 || dek_nonce.len() != 12 {
        return Err(CryptoError::CorruptEnvelope);
    }

    let mut kek = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha512>::new(Some(&kdf_salt), unseal_key);
    hk.expand(KEK_INFO, kek.as_mut())
        .map_err(|_| CryptoError::CorruptEnvelope)?;

    let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| CryptoError::AeadFailure)?;
    let decrypted_dek = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&dek_nonce),
                Payload {
                    msg: &wrapped_dek,
                    aad: ENVELOPE_AAD,
                },
            )
            .map_err(|_| CryptoError::InvalidUnsealKey)?,
    );

    if decrypted_dek.len() != 32 {
        return Err(CryptoError::CorruptEnvelope);
    }

    let mut dek_arr = Zeroizing::new([0u8; 32]);
    dek_arr.copy_from_slice(&decrypted_dek);
    Ok(dek_arr)
}

/// Create a new wrapped DEK envelope from a 256-bit unseal key, returning:
/// `(EnvelopeHeader, sqlcipher_db_key, value_aead_key, audit_chain_key)`.
pub fn create_envelope(
    unseal_key: &[u8; 32],
) -> Result<(EnvelopeHeader, LockedKey, LockedKey, LockedKey), CryptoError> {
    let mut master_dek = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(master_dek.as_mut());

    let header = wrap_master_dek_with_unseal_key(unseal_key, &master_dek)?;
    let (db_key, aead_key, audit_key) = derive_subkeys(&master_dek)?;

    Ok((header, db_key, aead_key, audit_key))
}

/// Verify and unwrap an existing `EnvelopeHeader` using the supplied unseal key.
/// Fails with `CryptoError::InvalidUnsealKey` if the AEAD tag check fails.
pub fn unwrap_envelope(
    unseal_key: &[u8; 32],
    header: &EnvelopeHeader,
) -> Result<(LockedKey, LockedKey, LockedKey), CryptoError> {
    let dek_arr = unwrap_raw_master_dek(unseal_key, header)?;
    derive_subkeys(&dek_arr)
}

/// Atomically re-wrap the existing `master_dek` under a newly generated 256-bit unseal key.
/// Invalidates the old unseal key on disk without requiring secret re-encryption or downtime.
pub fn rotate_envelope_unseal_key(
    current_unseal_key: &[u8; 32],
    current_header: &EnvelopeHeader,
) -> Result<(Zeroizing<[u8; 32]>, EnvelopeHeader), CryptoError> {
    let master_dek = unwrap_raw_master_dek(current_unseal_key, current_header)?;
    let new_unseal_key = generate_unseal_key();
    let new_header = wrap_master_dek_with_unseal_key(&new_unseal_key, &master_dek)?;
    Ok((new_unseal_key, new_header))
}

/// Harden process memory without `mlockall(MCL_FUTURE)` (which causes `ENOMEM` panics when
/// Tokio thread stacks or TLS buffers grow beyond `RLIMIT_MEMLOCK`).
/// Disables core dumps / ptrace via `PR_SET_DUMPABLE = 0` and verifies targeted `LockedKey`
/// `mlock()` availability for cryptographic key pages.
pub fn lock_process_memory() -> bool {
    #[cfg(unix)]
    unsafe {
        let dumpable_res = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if dumpable_res != 0 {
            tracing::warn!("prctl(PR_SET_DUMPABLE, 0) returned non-zero");
        }
        let mut probe = [0xAAu8; 32];
        match LockedKey::from_mut_array(&mut probe) {
            Ok(k) => k.is_memory_locked(),
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn derive_subkeys(master_dek: &[u8; 32]) -> Result<(LockedKey, LockedKey, LockedKey), CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, master_dek);
    let mut db_raw = Zeroizing::new([0u8; 32]);
    let mut aead_raw = Zeroizing::new([0u8; 32]);
    let mut audit_raw = Zeroizing::new([0u8; 32]);
    hk.expand(SQLCIPHER_KEY_INFO, db_raw.as_mut())
        .map_err(|_| CryptoError::AeadFailure)?;
    hk.expand(VALUE_AEAD_KEY_INFO, aead_raw.as_mut())
        .map_err(|_| CryptoError::AeadFailure)?;
    hk.expand(AUDIT_CHAIN_KEY_INFO, audit_raw.as_mut())
        .map_err(|_| CryptoError::AeadFailure)?;

    let db_key = LockedKey::from_mut_array(&mut db_raw)?;
    let aead_key = LockedKey::from_mut_array(&mut aead_raw)?;
    let audit_key = LockedKey::from_mut_array(&mut audit_raw)?;
    Ok((db_key, aead_key, audit_key))
}

/// Compute an RFC 2104 HMAC-SHA512 digest over length-prefixed tamper-evident audit fields.
pub fn compute_audit_chain_mac(
    audit_key: &LockedKey,
    prev_mac_hex: &str,
    seq: i64,
    timestamp: i64,
    event_type: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
) -> String {
    let mut ipad = Zeroizing::new([0x36u8; 128]);
    let mut opad = Zeroizing::new([0x5cu8; 128]);
    for (i, &b) in audit_key.as_bytes().iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }

    let mut inner = Sha512::new();
    inner.update(ipad.as_slice());
    inner.update(b"sv:v2:audit:");
    for field in [
        prev_mac_hex.as_bytes(),
        &seq.to_be_bytes(),
        &timestamp.to_be_bytes(),
        event_type.as_bytes(),
        actor.as_bytes(),
        resource.as_bytes(),
        outcome.as_bytes(),
    ] {
        inner.update((field.len() as u64).to_be_bytes());
        inner.update(field);
    }
    let mut inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad.as_slice());
    outer.update(inner_digest.as_slice());
    inner_digest.as_mut_slice().zeroize();
    let mut outer_digest = outer.finalize();
    let mac_hex = hex_encode(outer_digest.as_slice());
    outer_digest.as_mut_slice().zeroize();
    mac_hex
}

/// Construct canonical Associated Data (AAD) binding a secret ciphertext to its exact path, project, and version.
pub fn build_secret_aad(project: &str, canonical_path: &str, version: i64) -> Vec<u8> {
    format!("sv:v2:{project}:{canonical_path}:{version}").into_bytes()
}

/// Encrypt a secret value with AES-256-GCM bound to canonical `(project, path, version)` AAD.
pub fn encrypt_secret_with_aad(
    key: &LockedKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::AeadFailure)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt and authenticate an AES-256-GCM secret value against its expected AAD.
pub fn decrypt_secret_with_aad(
    key: &LockedKey,
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::AeadFailure)?;

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)?;

    Ok(Zeroizing::new(plaintext))
}

/// Mint a high-entropy machine token:
/// - `token_id`: `tok_<32-hex>` (128-bit random identifier)
/// - `raw_token`: `sv_live_<32-hex-id>_<64-hex-secret>` (256-bit CSPRNG secret)
/// - `token_hash_sha512`: 128-hex SHA-512 digest of the 32-byte secret
pub fn mint_machine_token() -> (String, Zeroizing<String>, String) {
    let mut id_bytes = [0u8; 16];
    let mut sec_bytes = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut id_bytes);
    rand::thread_rng().fill_bytes(sec_bytes.as_mut());

    let id_hex = hex_encode(id_bytes);
    let sec_hex = Zeroizing::new(hex_encode(sec_bytes.as_ref()));

    let token_id = format!("tok_{id_hex}");
    let raw_token = Zeroizing::new(format!("sv_live_{id_hex}_{}", sec_hex.as_str()));
    let hash_hex = hash_bytes_sha512_hex(sec_bytes.as_ref());

    (token_id, raw_token, hash_hex)
}

/// Parse a `sv_live_<id_hex>_<secret_hex>` (or `sv_admin_<id_hex>_<secret_hex>`) bearer token into `(token_id, secret_bytes)`.
pub fn parse_machine_token(raw_header: &str) -> Result<(String, Zeroizing<[u8; 32]>), ()> {
    let body = raw_header
        .strip_prefix("sv_live_")
        .or_else(|| raw_header.strip_prefix("sv_admin_"))
        .ok_or(())?;
    let (id_hex, sec_hex) = body.split_once('_').ok_or(())?;
    if id_hex.len() != 32 || sec_hex.len() != 64 {
        return Err(());
    }
    let _ = hex_decode(id_hex)?;
    let decoded_sec = Zeroizing::new(hex_decode(sec_hex)?);
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&decoded_sec);
    Ok((format!("tok_{id_hex}"), arr))
}

/// Compute hex-encoded SHA-512 digest.
pub fn hash_bytes_sha512_hex(data: &[u8]) -> String {
    let digest = Sha512::digest(data);
    hex_encode(digest)
}

/// Verify a 32-byte token secret against an expected hex-encoded SHA-512 digest in constant time.
pub fn verify_token_sha512_ct(candidate_secret: &[u8; 32], expected_sha512_hex: &str) -> bool {
    let expected_bytes = match hex_decode(expected_sha512_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let candidate_digest = Sha512::digest(candidate_secret);
    bool::from(candidate_digest.as_slice().ct_eq(expected_bytes.as_slice()))
}

/// Constant-time string comparison via fixed-width SHA-512 digests (prevents length & byte timing leaks).
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let da = Sha512::digest(a.as_bytes());
    let db = Sha512::digest(b.as_bytes());
    let len_eq = (a.len() as u64).ct_eq(&(b.len() as u64));
    bool::from(da.as_slice().ct_eq(db.as_slice()) & len_eq)
}

pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let Ok(byte) = u8::from_str_radix(&s[i..i + 2], 16) else {
            out.zeroize();
            return Err(());
        };
        out.push(byte);
    }
    Ok(out)
}

/// Convert Unix epoch days (`days_since_1970`) into Gregorian `(year, month, day)`.
fn civil_from_unix_days(days_since_epoch: i64) -> (i32, u8, u8) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u8, d as u8)
}

/// Generate a CA/Browser-Forum-compliant (`< 398` days) self-signed ECDSA P-256 X.509 certificate
/// and private key using `rcgen`. Returns `(cert_pem, key_pem, fingerprint_sha256)`.
pub fn generate_self_signed_tls_cert(
    san_list: &[String],
) -> Result<(String, String, String), String> {
    let subject_alt_names: Vec<String> = if san_list.is_empty() {
        vec!["localhost".to_string(), "127.0.0.1".to_string()]
    } else {
        san_list.to_vec()
    };

    let mut params = rcgen::CertificateParams::new(subject_alt_names)
        .map_err(|e| format!("Invalid TLS SAN list: {e}"))?;
    let now_days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(20_454);
    let (y1, m1, d1) = civil_from_unix_days(now_days.saturating_sub(1));
    let (y2, m2, d2) = civil_from_unix_days(now_days.saturating_add(396));
    params.not_before = rcgen::date_time_ymd(y1, m1, d1);
    params.not_after = rcgen::date_time_ymd(y2, m2, d2);

    let signing_key = rcgen::KeyPair::generate()
        .map_err(|e| format!("Failed generating ECDSA TLS keypair: {e}"))?;
    let cert = params
        .self_signed(&signing_key)
        .map_err(|e| format!("Failed generating self-signed TLS certificate: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let cert_der = cert.der();

    use sha2::Sha256;
    let digest = Sha256::digest(cert_der);
    let fingerprint_hex = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(":");

    Ok((cert_pem, key_pem, fingerprint_hex))
}

/// Construct a `rustls::ServerConfig` that strictly negotiates **TLS 1.3 only**
/// (rejecting TLS 1.2 or older handshakes even if Cargo feature unification enables `tls12` in `rustls`).
pub fn build_strict_tls13_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    let _ = rustls::crypto::ring::default_provider().install_default();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed parsing TLS certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("TLS certificate PEM contained zero X.509 certificates".to_string());
    }

    let priv_key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| format!("Failed parsing TLS private key PEM: {e}"))?;

    let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, priv_key)
        .map_err(|e| format!("Failed constructing strict TLS 1.3 ServerConfig: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Compute the SHA-256 fingerprint in colon-separated uppercase hex (`AA:BB:CC:...`)
/// from a PEM-encoded X.509 certificate string.
pub fn compute_pem_fingerprint(pem_str: &str) -> Option<String> {
    use base64::Engine;
    let mut b64 = String::new();
    let mut in_cert = false;

    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if trimmed == "-----END CERTIFICATE-----" {
            in_cert = false;
            if let Ok(der_bytes) = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes())
            {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(&der_bytes);
                return Some(
                    digest
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<String>>()
                        .join(":"),
                );
            }
        } else if in_cert {
            b64.push_str(trimmed);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert_and_strict_tls13_config() {
        let (cert_pem, key_pem, fingerprint) =
            generate_self_signed_tls_cert(&["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("cert generation failed");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(fingerprint.split(':').count(), 32);

        let parsed_fp = compute_pem_fingerprint(&cert_pem).expect("failed parsing PEM cert");
        assert_eq!(parsed_fp, fingerprint);

        let _tls13 = build_strict_tls13_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
            .expect("strict TLS 1.3 config failed");
    }

    #[test]
    fn test_rotate_envelope_unseal_key_preserves_subkeys_and_invalidates_old_key() {
        let old_key = generate_unseal_key();
        let (old_hdr, db1, aead1, aud1) = create_envelope(&old_key).expect("create envelope");

        let (new_key, new_hdr) =
            rotate_envelope_unseal_key(&old_key, &old_hdr).expect("rotate unseal key");
        assert_ne!(old_key.as_ref(), new_key.as_ref());

        // Old key must fail against rotated header
        assert!(unwrap_envelope(&old_key, &new_hdr).is_err());

        // New key must derive identical subkeys so SQLCipher + secret ciphertexts remain valid
        let (db2, aead2, aud2) = unwrap_envelope(&new_key, &new_hdr).expect("unwrap rotated");
        assert_eq!(db1.as_bytes(), db2.as_bytes());
        assert_eq!(aead1.as_bytes(), aead2.as_bytes());
        assert_eq!(aud1.as_bytes(), aud2.as_bytes());
    }
}
