use crate::pinset::{
    keychain::SecureKey,
    types::{AeadAlgorithm, PinsetError, PinsetHeader, Result as PinsetResult},
};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};

#[allow(deprecated)]
pub(crate) fn encrypt_body(
    header: &PinsetHeader,
    kek: &SecureKey,
    plaintext: &[u8],
) -> PinsetResult<Vec<u8>> {
    match header.aead_alg {
        AeadAlgorithm::AesGcm => {
            let key_bytes = kek.as_bytes();
            if key_bytes.len() != 32 {
                return Err(PinsetError::Invalid("KEK must be 32 bytes for AES-256-GCM"));
            }
            let key = Key::<Aes256Gcm>::from_slice(key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&header.nonce);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| PinsetError::Invalid("AEAD encrypt failed"))
        }
    }
}

#[allow(deprecated)]
pub(crate) fn decrypt_body(
    header: &PinsetHeader,
    kek: &SecureKey,
    plaintext: &[u8],
) -> PinsetResult<Vec<u8>> {
    match header.aead_alg {
        AeadAlgorithm::AesGcm => {
            let key_bytes = kek.as_bytes();
            if key_bytes.len() != 32 {
                return Err(PinsetError::Invalid("KEK must be 32 bytes for AES-256-GCM"));
            }
            let key = Key::<Aes256Gcm>::from_slice(key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&header.nonce);
            cipher
                .decrypt(nonce, plaintext)
                .map_err(|_| PinsetError::Invalid("AEAD encrypt failed"))
        }
    }
}
