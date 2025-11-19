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
    pub fn with_description(mut self, desc: impl Into<Box<str>>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Securely stored key data with automatic zeroization
// #[derive(Clone)]
pub struct SecureKey {
    data: Zeroizing<Box<[u8]>>,
}

impl SecureKey {
    // pub fn new(data: impl AsRef<[u8]>) -> Self {
    //     Self {
    //         data: Zeroizing::new(data.as_ref().into()),
    //     }
    // }

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
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SecureKey {
    //avoid sharing data but provide info
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey([REDACTED {} bytes])", self.len())
    }
}

// impl From<Vec<u8>> for SecureKey {
//     fn from(data: Vec<u8>) -> Self {
//         Self::new(data)
//     }
// }

// impl From<&[u8]> for SecureKey {
//     fn from(data: &[u8]) -> Self {
//         Self::new(data)
//     }
// }

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

    pub fn delete_key(&self, identifier: &KeyIdentifier) -> KeychainResult<()> {
        // Acquire lock to serialise keychain access
        let _guard = self.lock.lock().map_err(|_| KeychainError::LockPoisoned)?;

        let entry = self.create_entry(identifier)?;

        entry.delete_credential().map_err(KeychainError::from)
    }

    /// Check if a key exists in the keychain
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
#[derive(Debug, Clone)]
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
    pub cross_platform: bool,

    /// Supports binary secrets (not just strings)
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

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER

// MOVE THESE TESTS AFTER
#[test]
fn test_key_identifier_creation() {
    let id = KeyIdentifier::new("test-service", "test-account");
    assert_eq!(id.service, "test-service".into());
    assert_eq!(id.account, "test-account".into());
    assert_eq!(id.label, None);
}

#[test]
fn test_key_identifier_builder() {
    let id = KeyIdentifier::new("service", "account").with_label("My Key");

    assert_eq!(id.label, Some("My Key".into()));
}

#[test]
fn test_key_identifier_unique_string() {
    let id = KeyIdentifier::new("my-service", "my-account");
    assert_eq!(id.to_unique_string(), "my-service/my-account");
    assert_eq!(id.to_string(), "my-service/my-account");
}

#[test]
fn test_key_attributes_builder() {
    let id = KeyIdentifier::new("service", "account");
    let attrs = KeyAttributes::new(id.clone()).with_description("Test key");

    assert_eq!(attrs.identifier, id);
    assert_eq!(attrs.description, Some("Test key".to_string().into()));
}

#[test]
fn test_secure_key_creation() {
    let data = vec![1, 2, 3, 4, 5];
    // let key = SecureKey::new(data.clone());
    let key = SecureKey::from_slice(&data);

    assert_eq!(key.as_bytes(), &data[..]);
    assert_eq!(key.len(), 5);
    assert!(!key.is_empty());
}

#[test]
fn test_secure_key_debug() {
    // let key = SecureKey::new(vec![1, 2, 3, 4, 5]);
    let key = SecureKey::from_vec(vec![1, 2, 3, 4, 5]);
    let debug_str = format!("{key:?}");
    assert!(debug_str.contains("REDACTED"));
    assert!(debug_str.contains("5 bytes"));
    // Ensure actual data is not in debug output
    assert!(!debug_str.contains("1"));
}

#[test]
fn test_secure_key_from_vec() {
    let data = vec![1, 2, 3];
    let keep = data.clone();
    let key: SecureKey = data.into();
    assert_eq!(key.as_bytes(), &keep[..]);
}

#[test]
fn test_secure_key_from_slice() {
    let data: &[u8] = &[1, 2, 3, 4];
    // let key: SecureKey = data.into();
    let key: SecureKey = data.into();
    assert_eq!(key.as_bytes(), data);
}

#[test]
fn test_kek_identifier_for_store() {
    let store_id = [0u8; 16];
    let id = kek_identifier_for_store(&store_id);

    assert_eq!(id.service, "com.p2p-password-manager.pinset".into());
    assert!(id.account.starts_with("kek-"));
    assert!(id.label.is_some());
}

#[test]
fn test_keychain_creation() {
    let result = Keychain::new();
    assert!(result.is_ok());
}

#[test]
fn test_default_keychain() {
    let result = default_keychain();
    assert!(result.is_ok());
}

#[test]
fn test_platform_info() {
    let keychain = Keychain::new().unwrap();
    let info = keychain.platform_info();

    assert!(!info.name.is_empty());
    assert!(info.features.cross_platform);
    assert!(info.features.binary_secrets);
}

#[test]
fn test_store_and_retrieve_key() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let test_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    // let key = SecureKey::new(test_data.clone());
    let key = SecureKey::from_vec(test_data.clone());

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-key-{}", std::process::id()),
    );

    let attributes = KeyAttributes::new(identifier.clone());

    // Clean up any existing test key
    let _ = keychain.delete_key(&identifier);

    // Store the key
    let store_result = keychain.store_key(key, attributes);
    assert!(
        store_result.is_ok(),
        "Failed to store key: {:?}",
        store_result.err()
    );

    // Retrieve the key
    let retrieved = keychain.retrieve_key(&identifier);
    assert!(
        retrieved.is_ok(),
        "Failed to retrieve key: {:?}",
        retrieved.err()
    );

    let retrieved_key = retrieved.unwrap();
    assert_eq!(retrieved_key.as_bytes(), &test_data[..]);

    // Clean up
    let delete_result = keychain.delete_key(&identifier);
    assert!(
        delete_result.is_ok(),
        "Failed to delete key: {:?}",
        delete_result.err()
    );
}

#[test]
fn test_key_exists() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-exists-{}", std::process::id()),
    );

    // Clean up any existing test key
    let _ = keychain.delete_key(&identifier);

    // Should not exist initially
    let exists = keychain.key_exists(&identifier);
    assert!(exists.is_ok());
    assert!(!exists.unwrap());

    // Store a key
    // let key = SecureKey::new(vec![1, 2, 3]);
    let key = SecureKey::from_vec(vec![1, 2, 3]);
    let attributes = KeyAttributes::new(identifier.clone());
    keychain
        .store_key(key, attributes)
        .expect("Failed to store key");

    // Should exist now
    let exists = keychain.key_exists(&identifier);
    assert!(exists.is_ok());
    assert!(exists.unwrap());

    // Clean up
    keychain
        .delete_key(&identifier)
        .expect("Failed to delete key");
}

#[test]
fn test_update_key() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-update-{}", std::process::id()),
    );

    // Clean up any existing test key
    let _ = keychain.delete_key(&identifier);

    // Store initial key
    // let key1 = SecureKey::new(vec![1, 2, 3]);
    let key1 = SecureKey::from_vec(vec![1, 2, 3]);
    let attributes = KeyAttributes::new(identifier.clone());
    keychain
        .store_key(key1, attributes.clone())
        .expect("Failed to store key");

    // Update with new data
    // let key2 = SecureKey::new(vec![4, 5, 6]);
    let key2 = SecureKey::from_vec(vec![4, 5, 6]);
    let update_result = keychain.update_key(key2, attributes);
    assert!(
        update_result.is_ok(),
        "Failed to update key: {:?}",
        update_result.err()
    );

    // Retrieve and verify
    let retrieved = keychain
        .retrieve_key(&identifier)
        .expect("Failed to retrieve key");
    assert_eq!(retrieved.as_bytes(), &[4, 5, 6]);

    // Clean up
    keychain
        .delete_key(&identifier)
        .expect("Failed to delete key");
}

#[test]
fn test_delete_nonexistent_key() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-nonexistent-{}", std::process::id()),
    );

    // Ensure it doesn't exist
    let _ = keychain.delete_key(&identifier);

    // Try to delete again - keyring may return NoEntry error
    let result = keychain.delete_key(&identifier);
    assert!(result.is_err());
}

#[test]
fn test_retrieve_nonexistent_key() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-nonexistent-{}", std::process::id()),
    );

    let result = keychain.retrieve_key(&identifier);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeychainError::NotFound(_)));
}

#[test]
fn test_store_duplicate_key() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-duplicate-{}", std::process::id()),
    );

    // Clean up any existing test key
    let _ = keychain.delete_key(&identifier);

    // Store first key
    // let key1 = SecureKey::new(vec![1, 2, 3]);
    let key1 = SecureKey::from_vec(vec![1, 2, 3]);
    let attributes = KeyAttributes::new(identifier.clone());
    keychain
        .store_key(key1, attributes.clone())
        .expect("Failed to store first key");

    // Try to store again with same identifier
    // let key2 = SecureKey::new(vec![4, 5, 6]);
    let key2 = SecureKey::from_vec(vec![4, 5, 6]);
    let result = keychain.store_key(key2, attributes);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        KeychainError::AlreadyExists(_)
    ));

    // Clean up
    keychain
        .delete_key(&identifier)
        .expect("Failed to delete key");
}

#[test]
fn test_update_nonexistent_key() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-update-nonexistent-{}", std::process::id()),
    );

    // Ensure it doesn't exist
    let _ = keychain.delete_key(&identifier);

    // Try to update non-existent key
    // let key = SecureKey::new(vec![1, 2, 3]);
    let key = SecureKey::from_vec(vec![1, 2, 3]);
    let attributes = KeyAttributes::new(identifier);
    let result = keychain.update_key(key, attributes);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeychainError::NotFound(_)));
}

#[test]
fn test_binary_secret_storage() {
    let keychain = Keychain::new().expect("Failed to create keychain");

    // Test with binary data that's not valid UTF-8
    let binary_data = vec![0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02];
    // let key = SecureKey::new(binary_data.clone());
    let key = SecureKey::from_vec(binary_data.clone());

    let identifier = KeyIdentifier::new(
        "com.p2p-password-manager.test".into(),
        format!("test-binary-{}", std::process::id()),
    );

    let attributes = KeyAttributes::new(identifier.clone());

    // Clean up any existing test key
    let _ = keychain.delete_key(&identifier);

    // Store binary data
    keychain
        .store_key(key, attributes)
        .expect("Failed to store binary key");

    // Retrieve and verify
    let retrieved = keychain
        .retrieve_key(&identifier)
        .expect("Failed to retrieve binary key");
    assert_eq!(retrieved.as_bytes(), &binary_data[..]);

    // Clean up
    keychain
        .delete_key(&identifier)
        .expect("Failed to delete key");
}
