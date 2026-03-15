use core::fmt;

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::TryRng;
use rand::rngs::SysRng;

pub enum CryptoError {
    NonceFailed,
    EncryptionFailed,
    DecryptionFailed
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::NonceFailed => write!(f, "Failed to generate nonce"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed — data may be corrupted or tampered"),
        }
    }
}

pub fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; 12];

    let mut rng = SysRng::default();

    rng.try_fill_bytes(&mut nonce_bytes).map_err(|_| CryptoError::NonceFailed)?;

    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher.encrypt(&nonce, data).map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((ciphertext, nonce_bytes))

}