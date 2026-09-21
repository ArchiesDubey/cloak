//! Cryptographic primitives: Argon2id KDF and XChaCha20-Poly1305 authenticated encryption.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Derives a 256-bit encryption key from a passphrase and salt using Argon2id.
/// Follows OWASP/NIST guidelines (64MB memory, 3 iterations, 4 parallelism).
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
        .map_err(|e| anyhow!("Failed to configure Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;

    Ok(key)
}

/// Generates a cryptographically secure random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random nonce for XChaCha20-Poly1305.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext bytes using XChaCha20-Poly1305 AEAD.
/// Returns (nonce, ciphertext_with_tag).
pub fn encrypt_bytes(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption error: {e}"))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypts ciphertext bytes using XChaCha20-Poly1305 AEAD.
/// Returns zeroized plaintext bytes upon success.
pub fn decrypt_bytes(
    key: &[u8; KEY_LEN],
    nonce_bytes: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: invalid key, corrupted data, or authentication failure"))?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_roundtrip() {
        let password = b"super-secure-master-password";
        let salt = generate_salt();
        let key = derive_key(password, &salt).expect("Key derivation failed");

        let original_data = b"MY_SECRET_API_KEY=sk-test-123456789";
        let (nonce, ciphertext) = encrypt_bytes(&key, original_data).expect("Encryption failed");

        let decrypted = decrypt_bytes(&key, &nonce, &ciphertext).expect("Decryption failed");
        assert_eq!(&*decrypted, original_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let password = b"password123";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();

        let data = b"sensitive-data";
        let (nonce, mut ciphertext) = encrypt_bytes(&key, data).unwrap();

        // Tamper with the last byte
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_bytes(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let salt = generate_salt();
        let key1 = derive_key(b"password-1", &salt).unwrap();
        let key2 = derive_key(b"password-2", &salt).unwrap();

        let data = b"payload";
        let (nonce, ciphertext) = encrypt_bytes(&key1, data).unwrap();

        let result = decrypt_bytes(&key2, &nonce, &ciphertext);
        assert!(result.is_err());
    }
}
