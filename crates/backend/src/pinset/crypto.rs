//! AEAD encryption and decryption helpers
//!
//! # Overview
//!
//! This module provides a low-level cryptographic operations used by [`PinsetStore`](crate::pinset::store::PinsetStore) implementation.
//! It is not intended to be part of the public API surface.
//!
//! The functions here perform authenticated encryption of the *store body*
//! (serialized [`PinsetRecord`](crate::pinset::types::PinsetRecord) values)
//! using the AEAD algorithm specified in the [`PinsetHeader`](crate::pinset::types::PinsetHeader):
//!
//! - Currently, only AES-256-GCM is supported.
//! - The KEK is supplied externally (via the OS keychain or passphrase-derived KDF).
//! - The nonce is taken directly from `header.nonce`, which is derived deterministically in `PinsetStore` using `derive_nonce(store_id, seq)`.
//!
//! These helpers enforce:
//! - KEK must be exactly 32 bytes for AES-256-GCM.
//! - AEAD errors (authentication failure, nonce mismatch, corrupted ciphertext) are converted into
//! high-level [`PinsetError`](crate::pinset::types::PinsetError).
//!
//! # Security Notes
//!
//! * These functions do not generate keys or nonces themselves;
//! they rely on `PinsetStore` to provide correct inputs.
//! * AES-GCM requires unique nonces for a given key. This invariant is guaranteed by the monotonic `seq` and deterministic nonce derivation in `PinsetStore::save_inner`.
//! * Authentication tags are stored alongside ciphertext implicitly via the AES-GCM output format.
//!
//! # Errors
//!
//! These functions return a ['PinsetResult](crate::pinset::types::Result) which may fail if:
//!
//! - The KEK length is invalid.
//! - AEAD encryption/decryption fails (bad nonce, corrupted ciphertext, wrong KEK).
//!
//! These errors propagate cleanly through the higher-level store API.

use crate::pinset::{
    keychain::SecureKey,
    types::{AeadAlgorithm, PinsetError, PinsetHeader, Result as PinsetResult},
};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};

/// Encrypts teh serialized body using the KEK and nonce from the header.
///
/// # Arguments
///
/// * `header` - The parsed pinset header containing AEAD configuration and nonce.
/// * `kek` - The 256-bit Key Encryption Key obtained from the OS keychain or KDF.
/// * `plaintext` - The serialized `PinsetBody` bytes.
///
/// # Returns
///
/// A `Vec<u8>` containing the AES-GCM ciphertext and authentication tag.
///
/// # Errors
///
/// Returns [`PinsetError::Invalid`] if:
/// * `kek` is not exactly 32 bytes.
/// * AES-GCM encryption fails.
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

/// Decrypts an encrypted pinset body using the KEK and nonce from the header.
///
/// # Arguments
///
/// * `header` – The pinset header used to interpret AEAD parameters.
/// * `kek` – The 256-bit Key Encryption Key.
/// * `plaintext` – The AES-GCM ciphertext bytes (ciphertext + tag).
///
/// # Returns
///
/// A `Vec<u8>` containing the decrypted plaintext body.
///
/// # Errors
///
/// Returns [`PinsetError::Invalid`] if:
/// * `kek` is not exactly 32 bytes.
/// * AES-GCM authentication fails (bad key, wrong nonce, corrupted ciphertext).
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
