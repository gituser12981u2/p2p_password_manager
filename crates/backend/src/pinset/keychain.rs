//! OS keychain integration for PinsetStore (PSET) key management.
//! 
//! # Role int he PSET format
//! 
//! A PSET file contains an unencrypted header and an AEAD-sealed body.
//! The header declares a `key_source` that determines how the Key Encrypted Key (KEKE)
//! is obtained. For `KeySource::OsKeyStore`, the KEK is retrieved from the platform
//! credential store (macOS keychain, Windows Credential Manager, Secret Service, etc.).
//! 
//! This module provides a thin, cross-platform wrapper over the [`keyring`] crate to:
//! 
//! - Store a newly generated KEK under a stable identifier derived form `store_id`.
//! - Retrieve the KEK for a given `store_id` to encrypt/decrypt the PSET body.
//! - Optionally, update/delete keys during lifecycle events (rotation, teardown).
//! 
//! The KEK returned by this module is fed into the AEAD helpers (e.g. AES-256-GCM).
//! THose helpers enforce key length (32 bytes for AES-GCM) and treat authentication
//! failures as high-level `PinsetError`.
//! 
//! # Identifiers and correlation resistance
//! 
//! To reduce the ability to correlate keychain entries with a specific store, the helpers
//! [`kek_identifier_for_store`] hashes the `store_id` using BLAKE3 and encodes the hash with base32 (without padding)
//! to derive a key name. This ensures that someone with access to a user's credential manager cannot correlate entries to specific keystores.
//! 
//! # Thread-safety and prompting behavior
//! 
//! Some platform backends may not be fully thread-safe, and some operations may trigger
//! OS UI prompts (e.g. access control dialogs). This wrapper serializes keychain calls
//! with a `Mutex` to reduce concurrency hazards.
//! 
//! Note: existence checks that call into teh OS credential store may still trigger prompts 
//! depending on platform configuration and keychain policy.
//! 
//! # Security notes
//! 
//! - Secrets are held in memory as [`zeroize::Zeroizing`] buffers to reduce lifetime after user.
//! - This module does not derive keys form passphrases; passphrase KDF is not handled yet as of 2025-12-19.
//! - Callers should treat all returned key material as sensitive and avoid logging it.
//! 
//! [`keyring`]: https://crates.io/crates/keyring 

use std::borrow::Cow;
use std::fmt;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Errors that can occur during keychain operations.
/// 
/// This error type is higher-level than the `keyring::Error` type and provides more context.
/// It normalizes platform-specific failure modes into cases the caller can handle (i.e missing key,
/// access denied, unsupported platform, etc.).
/// 
/// Some variants may be trigged by OS security UI flows (e.g. user cancellation or authentication required), depending on platform policy.
#[derive(thiserror::Error, Debug)]
pub enum KeychainError {
    /// The requred key does not exist in the credential store.
    #[error("key not found: {0}")]
    NotFound(Box<str>),

    /// The OS denied access (policy, permissions, locked keychain, etc.).
    #[error("access denied: {0}")]
    AccessDenied(Box<str>),

    /// The identifier was malformed or rejected by the platform.
    #[error("invalid key identifier: {0}")]
    InvalidIdentifier(Box<str>),

    /// A key already exists for the given identifier.
    #[error("key already exists: {0}")]
    AlreadyExists(Box<str>),

    /// The platform does not provide a supported credential store backend.
    #[error("operation not supported on this platform: {0}")]
    Unsupported(Box<str>),

    /// The user explicitly cancelled an OS prompt.
    #[error("user cancelled operation")]
    UserCancelled,

    /// The backend requires authentication (biometric / passcode / unlock) to proceed.
    #[error("authentication required")]
    AuthenticationRequired,

    /// Any platform-specific failure that doesn't map to the above variants.
    #[error("platform-specific error: {0}")]
    PlatformError(Box<str>),

    /// A `keyring` error that could not be mapped more specifically.
    #[error("keyring error: {0}")]
    Keyring(Box<str>),

    /// The internal lock was poisoned due to panic during a prior operation.
    #[error("lock poisoned: concurrent operation panicked")]
    LockPoisoned,

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Converts `keyring::Error` into this module's stable error surface.
/// 
/// The `keyring` crate unifies multiple backends; the exact error mapping may change
/// across versions/platforms. This conversion aims to preserve actionable semantics
/// for callers (missing key vs access denied vs bad id).
impl From<keyring::Error> for KeychainError {
    fn from(err: keyring::Error) -> Self {
        match err {
            keyring::Error::NoEntry => KeychainError::NotFound("Key not found in keychain".into()),
            keyring::Error::Invalid(_, _) => {
                KeychainError::InvalidIdentifier(err.to_string().into())
            }
            keyring::Error::PlatformFailure(e) => {
                KeychainError::PlatformError(e.to_string().into())
            }
            keyring::Error::Ambiguous(e) => {
                KeychainError::PlatformError(format!("Ambiguous credentials: {e:?}").into())
            }
            keyring::Error::NoStorageAccess(e) => KeychainError::AccessDenied(e.to_string().into()),
            keyring::Error::TooLong(field, _) => {
                KeychainError::InvalidIdentifier(format!("{field} is too long").into())
            }
            keyring::Error::BadEncoding(e) => {
                KeychainError::Keyring(format!("Bad encoding: {e:?}").into())
            }
            _ => KeychainError::Keyring(err.to_string().into()),
        }
    }
}

/// Result type for keychain operations.
pub type KeychainResult<T> = std::result::Result<T, KeychainError>;

/// Represents a key identifier that can be used to store/retrieve keys.
/// 
/// This maps to the `keyring::Entry` structure:
/// 
/// - `service`: service/application identifier (e.g. reverse-DNS string)
/// - `account`: per-secret name within the service (e.g. derived from store_id)
/// 
/// The `label` field is optional metadata intended for UI readability.
/// Some platforms may ignore or not persist it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyIdentifier {
    /// Service or application identifier (e.g., "com.example.p2p-password-manager"). 
    pub service: Box<str>,

    /// Account or key name (e.g., "kek-main", "store-abc123")
    pub account: Box<str>,

    /// Optional label for display purposes (stored as part of the identifier) 
    pub label: Option<Box<str>>,
}

impl KeyIdentifier {
    /// Create a new key identifier from a `service` and `account`.
    /// 
    /// Callers should treat the pair as stable over time; changing either field
    /// effectively "moves" the stored secret to a new location.
    pub fn new<A: AsRef<str>>(service: A, account: A) -> Self {
        Self {
            service: service.as_ref().into(),
            account: account.as_ref().into(),
            label: None,
        }
    }

    /// Attaches a human-readable label to the key identifier.
    /// 
    /// This is optional and may not be used by all platforms.
    pub fn with_label<A: AsRef<str>>(mut self, label: A) -> Self {
        self.label = Some(label.as_ref().into());
        self
    }

    /// Returns a unique string representation (`service/account`), primarily for logging
    /// and error messages. This string must not include secret material.
    pub fn to_unique_string(&self) -> String {
        format!("{}/{}", self.service, self.account)
    }
}

impl fmt::Display for KeyIdentifier {
    /// Displays the identifier as `service/account`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_unique_string())
    }
}

/// Attributes for storing a key in the keychain.
/// 
/// This is a small wrapper to keep API calls explicit and self-documenting.
#[derive(Debug, Clone)]
pub struct KeyAttributes {
    /// Identifier for the secret.
    pub identifier: KeyIdentifier,

    /// Optional description/comment
    pub description: Option<Box<str>>,
}

impl KeyAttributes {
    /// Create new key attributes with the given identifier.
    pub fn new(identifier: KeyIdentifier) -> Self {
        Self {
            identifier,
            description: None,
        }
    }

    /// Add a textual description.
    /// 
    /// Some keychain backends do not support arbitrary metadata; callers should not
    /// rely on this field being persisted. 
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_description(mut self, desc: impl Into<Box<str>>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// A secret key buffer that zeroizes on drop.
/// 
/// This type is used for KEKs and other sensitive data. It provides:
/// 
/// - Safe ownership of key bytes.
/// - Automatic memory zeroization on drop via [`Zeroizing`].
/// 
/// The contained bytes should never be logged or formatted. The `Debug` implementation
/// intentionally redacts content.
pub struct SecureKey {
    data: Zeroizing<Box<[u8]>>,
}

impl SecureKey {
    /// Copies key material from a borrowed slice.
    /// 
    /// Prefer [`SecureKey::from_vec`] when one already owns a `Vec<u8>` to avoid
    /// an extra allocation+copy.
    pub fn from_slice(s: &[u8]) -> Self {
        Self {
            data: Zeroizing::new(s.into()),
        }
    }

    /// Moves key material from an owned vector without copying.
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self {
            data: Zeroizing::new(v.into_boxed_slice()),
        }
    }

    /// Returns the raw key bytes.
    /// 
    /// Callers must treat this as sensitive data and avoid long-lived borrows. 
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the key in bytes. 
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the key is empty.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SecureKey {
    // Redacts key bytes while still conveying length. 
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey([REDACTED {} bytes])", self.len())
    }
}

impl From<Vec<u8>> for SecureKey {
    /// Converts an owned vector into a zeroizing key buffer.
    fn from(v: Vec<u8>) -> Self {
        SecureKey::from_vec(v)
    }
}

impl From<&[u8]> for SecureKey {
    /// Copies a borrowed slice into a zeroizing key buffer.
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

/// Cross-platform keychain interface used by PisnetStore.
/// 
/// This provides cross-platform secure key storage by wrapping around [`keyring::Entry`]. 
/// It serializes access via an internal mutex to avoid backend concurrency faults.
/// Keys are stored as binary secrets using `set_secret`/`get_secret`.
/// 
/// Typical PinsetStore usage timeline:
/// 
/// 1. Derive a stable [`KeyIdentifier`] from a `store_id` (see [`kek_identifier_for_store`]).
/// 2. Generate a random KEK and store it once via [`Keychain::store_key`].
/// 3. On load, retrieve the KEK via [`Keychain::retrieve_key`].
/// 4. Pass the KEK into the AEAD helpers to encrypt/decrypt the PSET body.
/// 
/// # Prompting caveat
/// 
/// Depending on OS policy, `store_key`, `retrieve_key`, and even existence checks may
/// trigger OS UI prompts (e.g. access control dialogs). This caller should be prepared to handle
/// cancellation/auth-required errors surfaced via [`KeychainError`]. 
pub struct Keychain {
    /// Serializes all keychain operations for thread-safety.
    lock: Mutex<()>,
}

impl Keychain {
    /// Constructs a new keychain wrapper.
    /// 
    /// This does not create any entires; it only initializes the wrapper. 
    pub fn new() -> KeychainResult<Self> {
        Ok(Self {
            lock: Mutex::new(()),
        })
    }

    /// Creates a backend entry handle for the given identifier.
    /// 
    /// This does not perform I/O by itself, but subsequent `get_secret`/`set_secret`
    /// operations may.
    fn create_entry(&self, identifier: &KeyIdentifier) -> KeychainResult<keyring::Entry> {
        keyring::Entry::new(&identifier.service, &identifier.account).map_err(KeychainError::from)
    }

    /// Stores a secret under `attributes.identifier`.
    /// 
    /// Returns [`KeychainError::AlreadyExists`] if the key is already present.
    /// Depending on platform policy, this operation may require user approval.
    /// 
    /// Security: the secret is written as raw bytes using `set_secret`.
    pub fn store_key(&self, key: SecureKey, attributes: KeyAttributes) -> KeychainResult<()> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(&attributes.identifier)?;

        // Check if key already exists
        // !! .get_secret() might prompt a window open on some OS's
        if entry.get_secret().is_ok() {
            return Err(KeychainError::AlreadyExists(
                attributes.identifier.to_string().into(),
            ));
        }

        // TODO: In the future, we should interact with our key_source flag here to know
        // if we want a passphrase KDF (i.e., the user sets a password to encrypt the file).
        entry
            .set_secret(key.as_bytes())
            .map_err(KeychainError::from)
    }

    /// Retrieves a secret previously stored under `identifier`.
    /// 
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    /// Depending on platform policy, this operation may require user authentication.
    pub fn retrieve_key(&self, identifier: &KeyIdentifier) -> KeychainResult<SecureKey> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(identifier)?;

        let bytes = entry.get_secret().map_err(KeychainError::from)?;

        Ok(SecureKey::from(bytes))
    }

    /// Updates an existing secret value.
    /// 
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn update_key(&self, key: SecureKey, attributes: KeyAttributes) -> KeychainResult<()> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(&attributes.identifier)?;

        // Check if key exists first
        if entry.get_secret().is_err() {
            return Err(KeychainError::NotFound(
                attributes.identifier.to_string().into(),
            ));
        }

        // Update the secret as hex-encoded bytes
        entry
            .set_secret(key.as_bytes())
            .map_err(KeychainError::from)
    }

    /// Deletes a stored secret.
    /// 
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn delete_key(&self, identifier: &KeyIdentifier) -> KeychainResult<()> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(identifier)?;

        entry.delete_credential().map_err(KeychainError::from)
    }

    /// Checks if a key exists in the keychain.
    /// 
    /// Warning: on some platforms this may prompt because it calls into the backend.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn key_exists(&self, identifier: &KeyIdentifier) -> KeychainResult<bool> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(identifier)?;

        // !! .get_secret() might prompt a window open on some OS's
        match entry.get_secret() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeychainError::from(e)),
        }
    }

    /// Returns platform-specific information about the keychain implementation
    ///
    /// Note: The keyring crate doesn't expose detailed platform info,
    /// so this returns basic information based on the target OS.
    /// 
    /// This is informational only; it does not guarantee a specific OS API.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn platform_info(&self) -> PlatformInfo {
        //no android support, annoying! To be added when keychain updates to 4.0
        #[cfg(target_os = "macos")]
        let name = "macOS Keychain (via keyring)";

        #[cfg(target_os = "ios")]
        let name = "iOS Keychain (via keyring)";

        #[cfg(target_os = "linux")]
        let name = "Linux Secret Service (via keyring)";

        #[cfg(target_os = "windows")]
        let name = "Windows Credential Manager (via keyring)";

        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "windows"
        )))]
        let name = "Unknown Platform (via keyring)";

        PlatformInfo {
            name: Cow::Borrowed(name),
            version: None,
            features: PlatformFeatures {
                cross_platform: true,
                binary_secrets: true,
            },
        }
    }
}

impl Default for Keychain {
    /// Constructs a default keychain wrapper.
    /// 
    /// Panics if initialization fails; prefer [`Keychain::new`] for error handling.
    fn default() -> Self {
        Self::new().expect("Failed to create keychain")
    }
}

/// Information about the platform-specific keychain implementation.
#[allow(dead_code)]
pub struct PlatformInfo {
    /// Human-readable platform name.
    pub name: Cow<'static, str>,

    /// Optional platform version or backend information.
    pub version: Option<String>,

    /// Feature flags supported by this wrapper.
    pub features: PlatformFeatures,
}

/// Feature flags for platform capabilities.
/// 
/// These are coarse-grained and reflect the wrapper's intended behavior rather than
/// every platform nuance.
#[derive(Debug, Clone, Default)]
pub struct PlatformFeatures {
    /// Works across multiple platforms
    #[cfg_attr(not(test), allow(dead_code))]
    pub cross_platform: bool,

    /// Supports binary secrets (not just strings)
    #[cfg_attr(not(test), allow(dead_code))]
    pub binary_secrets: bool,
}

/// Returns the default keychain wrapper for the current platform.
pub fn default_keychain() -> KeychainResult<Keychain> {
    Keychain::new()
}

/// Helper function to generate a Key Encryption Key (KEK) identifier for a PinsetStore `store_id`. 
///
/// 
/// The returned identifier is table: the same `store_id` always maps to the same keychain
/// entry name. 
/// 
/// This hashes the `store_id` using BLAKE3 and encodes with base32 (without padding) to prevent
/// correlation. This ensures that someone with access to a user's credential manager or
/// keystore cannot correlate entries to keystores.
/// 
/// This is the recommended identifier for `KeySource::OsKeyStore` when the file header
/// does not carry an explicit `kek_locator` TLV.
/// 
/// The label is a short human-readable display string intended to make the keychain UIs less opaque
/// without leaking the store id. It is optional and may not be used by all platforms.
pub fn kek_identifier_for_store(store_id: &[u8; 16]) -> KeyIdentifier {
    // Hash the store_id with BLAKE3 to prevent correlation
    let hash = blake3::hash(store_id);

    // Encode with base32 without padding to make it shorter and more readable
    let encoded = base32::encode(base32::Alphabet::Crockford, hash.as_bytes()).to_lowercase();

    KeyIdentifier::new(
        "com.p2p-password-manager.pinset",
        format!("kek-{encoded}").as_ref(),
    )
    .with_label(format!("Pinset KEK ({})", &encoded[..8]))
}

#[cfg(test)]
mod tests;
