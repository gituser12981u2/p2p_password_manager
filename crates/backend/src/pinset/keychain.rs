use std::borrow::Cow;
use std::fmt;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Errors that can occur during keychain operations
#[derive(thiserror::Error, Debug)]
pub enum KeychainError {
    //reduced error enum to 24 from 32 :)
    #[error("key not found: {0}")]
    NotFound(Box<str>),

    #[error("access denied: {0}")]
    AccessDenied(Box<str>),

    #[error("invalid key identifier: {0}")]
    InvalidIdentifier(Box<str>),

    #[error("key already exists: {0}")]
    AlreadyExists(Box<str>),

    #[error("operation not supported on this platform: {0}")]
    Unsupported(Box<str>),

    #[error("user cancelled operation")]
    UserCancelled,

    #[error("authentication required")]
    AuthenticationRequired,

    #[error("platform-specific error: {0}")]
    PlatformError(Box<str>),

    #[error("keyring error: {0}")]
    Keyring(Box<str>),

    #[error("lock poisoned: concurrent operation panicked")]
    LockPoisoned,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

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

/// Result type for keychain operations
pub type KeychainResult<T> = std::result::Result<T, KeychainError>;

/**
 Represents a key identifier that can be used to store/retrieve keys

 This maps to the keyring Entry structure:
 - service: The service/application identifier
 - account: The account/key name
*/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyIdentifier {
    /// Service or application identifier (e.g., "com.example.p2p-password-manager"), this will need to be changed TODO
    pub service: Box<str>,

    /// Account or key name (e.g., "kek-main", "store-abc123")
    pub account: Box<str>,

    /// Optional label for display purposes (stored as part of the identifier) (May delete this)
    pub label: Option<Box<str>>,
}

impl KeyIdentifier {
    /// Create a new key identifier
    pub fn new<A: AsRef<str>>(service: A, account: A) -> Self {
        Self {
            service: service.as_ref().into(),
            account: account.as_ref().into(),
            label: None,
        }
    }
    /// Set a display label
    pub fn with_label<A: AsRef<str>>(mut self, label: A) -> Self {
        self.label = Some(label.as_ref().into());
        self
    }

    pub fn to_unique_string(&self) -> String {
        format!("{}/{}", self.service, self.account)
    }
}

impl fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_unique_string())
    }
}

/**
 Attributes for storing a key in the keychain

*/
#[derive(Debug, Clone)]
pub struct KeyAttributes {
    /// Identifier for the key
    pub identifier: KeyIdentifier,

    /// Optional description/comment
    pub description: Option<Box<str>>,
}

impl KeyAttributes {
    /// Create new key attributes with the given identifier
    pub fn new(identifier: KeyIdentifier) -> Self {
        Self {
            identifier,
            description: None,
        }
    }

    /// Add a description
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_description(mut self, desc: impl Into<Box<str>>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Securely stored key data with automatic zeroization.
pub struct SecureKey {
    data: Zeroizing<Box<[u8]>>,
}

impl SecureKey {
    /// Copy from a borrowed slice
    pub fn from_slice(s: &[u8]) -> Self {
        Self {
            data: Zeroizing::new(s.into()),
        }
    }

    /// Move from an owned Vec without copying.
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self {
            data: Zeroizing::new(v.into_boxed_slice()),
        }
    }

    /// Get a reference to the key data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the key is empty
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SecureKey {
    // Avoid sharing data but provide info
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey([REDACTED {} bytes])", self.len())
    }
}

impl From<Vec<u8>> for SecureKey {
    fn from(v: Vec<u8>) -> Self {
        SecureKey::from_vec(v)
    }
}

impl From<&[u8]> for SecureKey {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

/**
Keychain implementation using the `keyring` crate

This provides cross-platform secure key storage by wrapping the keyring crate's
Entry API. Keys are stored as binary secrets using `set_secret`/`get_secret`.

Thread-safety: Uses a Mutex to serialise all keychain operations, ensuring that
concurrent access from multiple threads is handled safely. This is necessary because
the underlying OS keychain stores may not be thread-safe on all platforms.
*/
pub struct Keychain {
    /// Mutex to serialise all keychain operations for thread-safety
    lock: Mutex<()>,
}

impl Keychain {
    /// Create a new keychain instance
    pub fn new() -> KeychainResult<Self> {
        Ok(Self {
            lock: Mutex::new(()),
        })
    }

    /// Create a keyring Entry for the given identifier
    fn create_entry(&self, identifier: &KeyIdentifier) -> KeychainResult<keyring::Entry> {
        keyring::Entry::new(&identifier.service, &identifier.account).map_err(KeychainError::from)
    }

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

        // Store the secret as hex-encoded bytes to avoid platform encoding issues
        // Note: In the future, we should interact with our key_source flag here to know
        // if we want a passphrase KDF (i.e., the user sets a password to encrypt the file).
        // For now, we use get_secret/set_secret with hex encoding for reliable binary storage.
        entry
            .set_secret(key.as_bytes())
            .map_err(KeychainError::from)
    }

    pub fn retrieve_key(&self, identifier: &KeyIdentifier) -> KeychainResult<SecureKey> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(identifier)?;

        let bytes = entry.get_secret().map_err(KeychainError::from)?;

        Ok(SecureKey::from(bytes))
    }

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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn delete_key(&self, identifier: &KeyIdentifier) -> KeychainResult<()> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(identifier)?;

        entry.delete_credential().map_err(KeychainError::from)
    }

    /// Check if a key exists in the keychain
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

    /// Get platform-specific information about the keychain implementation
    ///
    /// Note: The keyring crate doesn't expose detailed platform info,
    /// so this returns basic information based on the target OS.
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
    fn default() -> Self {
        Self::new().expect("Failed to create keychain")
    }
}

/// Information about the platform-specific keychain implementation
#[allow(dead_code)]
pub struct PlatformInfo {
    /// Platform name
    pub name: Cow<'static, str>,

    /// Platform version or backend information
    pub version: Option<String>,

    /// Supported features
    pub features: PlatformFeatures,
}

/// Feature flags for platform capabilities
#[derive(Debug, Clone, Default)]
pub struct PlatformFeatures {
    /// Works across multiple platforms
    #[cfg_attr(not(test), allow(dead_code))]
    pub cross_platform: bool,

    /// Supports binary secrets (not just strings)
    #[cfg_attr(not(test), allow(dead_code))]
    pub binary_secrets: bool,
}

/// Get the default keychain implementation for the current platform
pub fn default_keychain() -> KeychainResult<Keychain> {
    Keychain::new()
}

/// Helper function to generate a Key Encryption Key (KEK) identifier for a pinset store
///
/// Hashes the store_id using BLAKE3 and encodes with base32 (without padding) to prevent
/// correlation. This ensures that someone with access to a user's credential manager or
/// keystore cannot correlate entries to keystores.
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
