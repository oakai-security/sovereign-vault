//! Cryptographic primitives: mmap/mlock RAM-pinned keys, HKDF-SHA512 envelope wrapping,
//! AES-256-GCM AEAD with Associated Data (AAD), and SHA-512 constant-time token hashing.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_AAD: &[u8] = b"sovereign-vault:v2:envelope";
const KEK_INFO: &[u8] = b"sovereign-vault:v2:kek";
const SQLCIPHER_KEY_INFO: &[u8] = b"sovereign-vault:v2:sqlcipher-db-key";
const VALUE_AEAD_KEY_INFO: &[u8] = b"sovereign-vault:v2:value-aead-key";
const AUDIT_CHAIN_KEY_INFO: &[u8] = b"sovereign-vault:v2:audit-chain-key";

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
            }

            let is_mlocked = libc::mlock(map_ptr, alloc_len) == 0;
            if !is_mlocked {
                tracing::warn!(
                    "mlock() returned non-zero (check container ulimits.memlock); zeroize-on-drop remains active"
                );
            }

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

/// Create a new wrapped DEK envelope from a 256-bit unseal key, returning:
/// `(EnvelopeHeader, sqlcipher_db_key, value_aead_key, audit_chain_key)`.
pub fn create_envelope(
    unseal_key: &[u8; 32],
) -> Result<(EnvelopeHeader, LockedKey, LockedKey, LockedKey), CryptoError> {
    let mut kdf_salt = [0u8; 32];
    let mut master_dek = Zeroizing::new([0u8; 32]);
    let mut dek_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut kdf_salt);
    rand::thread_rng().fill_bytes(master_dek.as_mut());
    rand::thread_rng().fill_bytes(&mut dek_nonce);

    let mut kek = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha512>::new(Some(&kdf_salt), unseal_key);
    hk.expand(KEK_INFO, kek.as_mut())
        .map_err(|_| CryptoError::AeadFailure)?;

    let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| CryptoError::AeadFailure)?;
    let wrapped_dek = cipher
        .encrypt(
            Nonce::from_slice(&dek_nonce),
            Payload {
                msg: master_dek.as_ref(),
                aad: ENVELOPE_AAD,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)?;

    let (db_key, aead_key, audit_key) = derive_subkeys(&master_dek)?;

    let header = EnvelopeHeader {
        version: 2,
        kdf: "hkdf-sha512".to_string(),
        kdf_salt_hex: hex_encode(kdf_salt),
        dek_nonce_hex: hex_encode(dek_nonce),
        wrapped_dek_hex: hex_encode(wrapped_dek),
    };

    Ok((header, db_key, aead_key, audit_key))
}

/// Verify and unwrap an existing `EnvelopeHeader` using the supplied unseal key.
/// Fails with `CryptoError::InvalidUnsealKey` if the AEAD tag check fails.
pub fn unwrap_envelope(
    unseal_key: &[u8; 32],
    header: &EnvelopeHeader,
) -> Result<(LockedKey, LockedKey, LockedKey), CryptoError> {
    if header.version != 2 || header.kdf != "hkdf-sha512" {
        return Err(CryptoError::CorruptEnvelope);
    }

    let kdf_salt = hex_decode(&header.kdf_salt_hex).map_err(|_| CryptoError::CorruptEnvelope)?;
    let dek_nonce = hex_decode(&header.dek_nonce_hex).map_err(|_| CryptoError::CorruptEnvelope)?;
    let wrapped_dek =
        hex_decode(&header.wrapped_dek_hex).map_err(|_| CryptoError::CorruptEnvelope)?;

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
    derive_subkeys(&dek_arr)
}

/// Lock all current and future process virtual memory pages (`mlockall(MCL_CURRENT | MCL_FUTURE)`)
/// when container `ulimits.memlock` permits, ensuring SQLCipher's internal C heap key schedule
/// and SQLite page caches are also pinned in RAM and never paged to swap.
pub fn lock_process_memory() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0
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
    let inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad.as_slice());
    outer.update(inner_digest);
    hex_encode(outer.finalize())
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

/// Parse a `sv_live_<id_hex>_<secret_hex>` bearer token into `(token_id, secret_bytes)`.
pub fn parse_machine_token(raw_header: &str) -> Result<(String, Zeroizing<[u8; 32]>), ()> {
    let body = raw_header.strip_prefix("sv_live_").ok_or(())?;
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
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Generate a self-signed X.509 certificate and private key using rcgen.
/// Returns `(cert_pem, key_pem, fingerprint_sha256)`.
pub fn generate_self_signed_tls_cert(
    san_list: &[String],
) -> Result<(String, String, String), String> {
    let subject_alt_names: Vec<String> = if san_list.is_empty() {
        vec!["localhost".to_string(), "127.0.0.1".to_string()]
    } else {
        san_list.to_vec()
    };

    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| format!("Failed to generate self-signed certificate: {e}"))?;

    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();
    let cert_der = certified_key.cert.der();

    use sha2::Sha256;
    let digest = Sha256::digest(cert_der);
    let fingerprint_hex = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<String>>()
        .join(":");

    Ok((cert_pem, key_pem, fingerprint_hex))
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
    fn test_generate_self_signed_cert() {
        let (cert_pem, key_pem, fingerprint) =
            generate_self_signed_tls_cert(&["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("cert generation failed");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(fingerprint.split(':').count(), 32);

        // Verify compute_pem_fingerprint recovers the exact same SHA-256 fingerprint
        let parsed_fp = compute_pem_fingerprint(&cert_pem).expect("failed parsing PEM cert");
        assert_eq!(parsed_fp, fingerprint);
    }
}
