//! Cryptographic primitives, mlock memory protection, and AEAD operations.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use secrecy::SecretString;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory-locked buffer that prevents OS swapping and zeros memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LockedKey {
    pub key_bytes: [u8; 32],
}

impl LockedKey {
    /// Allocate 32 bytes and lock them into physical RAM via mlock() on Unix.
    pub fn new(raw_bytes: [u8; 32]) -> Self {
        #[cfg(unix)]
        unsafe {
            // Lock memory pages to prohibit OS swap paging
            libc::mlock(
                raw_bytes.as_ptr() as *const libc::c_void,
                raw_bytes.len(),
            );
        }
        Self { key_bytes: raw_bytes }
    }
}

/// Encrypt a plaintext secret payload with AES-256-GCM authenticated encryption.
pub fn encrypt_secret(
    key: &LockedKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), String> {
    let cipher = Aes256Gcm::new_from_slice(&key.key_bytes)
        .map_err(|e| format!("Cipher init error: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt an AES-256-GCM ciphertext payload.
pub fn decrypt_secret(
    key: &LockedKey,
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key.key_bytes)
        .map_err(|e| format!("Cipher init error: {}", e))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error (authentication failed): {}", e))?;

    Ok(plaintext)
}
