/*

ISSUES: https://docs.rs/keyring/latest/keyring/ (found here)


Interoperability with Third Parties

Each of the platform-specific credential stores provided by this crate uses an underlying store
that may also be used by modules written in other languages. If you want to interoperate with these third party credential writers, then you will need to understand the details of how the target, service, and user of this crate’s generic model are used to identify credentials in the platform-specific store. These details are in the implementation of this crate’s secure-storage modules, and are documented in the headers of those modules.

(N.B. Since the included credential store implementations are platform-specific,
 you may need to use the Platform drop-down on docs.rs to view the storage module documentation for your desired platform.)
Caveats

This module expects passwords to be UTF-8 encoded strings,
so if a third party has stored an arbitrary byte string then retrieving that as a password will return a BadEncoding error. The returned error will have the raw bytes attached, so you can access them, but you can also just fetch them directly using get_secret rather than get_password.

While this crate’s code is thread-safe,
the underlying credential stores may not handle access from different threads reliably.
In particular, accessing the same credential from multiple threads at the same time can fail,
especially on Windows and Linux, because the accesses may not be serialized in the same order they are made.
 And for RPC-based credential stores such as the dbus-based Secret Service, accesses from multiple threads
 (and even the same thread very quickly) are not recommended, as they may cause the RPC mechanism to fail.


*/

use std::borrow::Cow;
use std::fmt;
use zeroize::Zeroizing;

/// Errors that can occur during keychain operations
#[derive(thiserror::Error, Debug)]
pub enum KeychainError {
    #[error("key not found: {0}")]
    NotFound(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("invalid key identifier: {0}")]
    InvalidIdentifier(String),

    #[error("key already exists: {0}")]
    AlreadyExists(String),

    #[error("operation not supported on this platform: {0}")]
    Unsupported(String),

    #[error("user cancelled operation")]
    UserCancelled,

    #[error("authentication required")]
    AuthenticationRequired,

    #[error("platform-specific error: {0}")]
    PlatformError(String),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<keyring::Error> for KeychainError {
    fn from(err: keyring::Error) -> Self {
        match err {
            keyring::Error::NoEntry => KeychainError::NotFound("Key not found in keychain".into()),
            keyring::Error::Invalid(_, _) => KeychainError::InvalidIdentifier(err.to_string()),
            keyring::Error::PlatformFailure(e) => KeychainError::PlatformError(e.to_string()),
            keyring::Error::Ambiguous(e) => {
                KeychainError::PlatformError(format!("Ambiguous credentials: {e:?}"))
            }
            keyring::Error::NoStorageAccess(e) => KeychainError::AccessDenied(e.to_string()),
            keyring::Error::TooLong(field, _) => {
                KeychainError::InvalidIdentifier(format!("{field} is too long"))
            }
            keyring::Error::BadEncoding(e) => {
                KeychainError::Keyring(format!("Bad encoding: {e:?}"))
            }
            _ => KeychainError::Keyring(err.to_string()),
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

//We need to add atomicity here, so it can only have 1 writer etc in the struct below, see copy pasted explanation at top of file
/**
 Attributes for storing a key in the keychain

*/
#[derive(Debug, Clone)]
pub struct KeyAttributes {
    /// Identifier for the key
    pub identifier: KeyIdentifier,

    /// Optional description/comment
    pub description: Option<String>,
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
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Securely stored key data with automatic zeroization
#[derive(Clone)]
pub struct SecureKey {
    data: Zeroizing<Box<[u8]>>,
}

impl SecureKey {
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        Self {
            data: Zeroizing::new(data.as_ref().into()),
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

impl From<Vec<u8>> for SecureKey {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureKey {
    fn from(data: &[u8]) -> Self {
        Self::new(data)
    }
}
/**
Keychain implementation using the `keyring` crate

This provides cross-platform secure key storage by wrapping the keyring crate's
Entry API. Keys are stored as binary secrets using `set_secret`/`get_secret`.

*/
pub struct Keychain {
    _private: (), // Prevent direct construction
}

impl Keychain {
    /// Create a new keychain instance
    pub fn new() -> KeychainResult<Self> {
        Ok(Self { _private: () })
    }

    /// Create a keyring Entry for the given identifier
    fn create_entry(&self, identifier: &KeyIdentifier) -> KeychainResult<keyring::Entry> {
        keyring::Entry::new(&identifier.service, &identifier.account).map_err(KeychainError::from)
    }

    pub fn store_key(&self, key: SecureKey, attributes: KeyAttributes) -> KeychainResult<()> {
        let entry = self.create_entry(&attributes.identifier)?;

        // Check if key already exists
        if entry.get_password().is_ok() {
            return Err(KeychainError::AlreadyExists(
                attributes.identifier.to_string(),
            ));
        }

        // Store the secret as hex-encoded string to avoid platform encoding issues
        //
        let hex_encoded = hex::encode(key.as_bytes());
        entry
            .set_password(&hex_encoded)
            .map_err(KeychainError::from)
    }

    pub fn retrieve_key(&self, identifier: &KeyIdentifier) -> KeychainResult<SecureKey> {
        let entry = self.create_entry(identifier)?;

        let hex_encoded = entry.get_password().map_err(KeychainError::from)?;

        // Decode hex string back to binary
        let decoded = hex::decode(hex_encoded)
            .map_err(|e| KeychainError::Keyring(format!("Failed to decode stored key: {e}")))?;

        Ok(SecureKey::new(decoded))
    }

    pub fn update_key(&self, key: SecureKey, attributes: KeyAttributes) -> KeychainResult<()> {
        let entry = self.create_entry(&attributes.identifier)?;

        // Check if key exists first
        if entry.get_password().is_err() {
            return Err(KeychainError::NotFound(attributes.identifier.to_string()));
        }

        // Update the secret as hex-encoded string
        let hex_encoded = hex::encode(key.as_bytes());
        entry
            .set_password(&hex_encoded)
            .map_err(KeychainError::from)
    }

    pub fn delete_key(&self, identifier: &KeyIdentifier) -> KeychainResult<()> {
        let entry = self.create_entry(identifier)?;

        entry.delete_credential().map_err(KeychainError::from)
    }

    /// Check if a key exists in the keychain
    pub fn key_exists(&self, identifier: &KeyIdentifier) -> KeychainResult<bool> {
        let entry = self.create_entry(identifier)?;

        match entry.get_password() {
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
        //no android support, annoying!
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
pub fn kek_identifier_for_store(store_id: &[u8; 16]) -> KeyIdentifier {
    let store_id_hex = hex::encode(store_id);
    KeyIdentifier::new(
        "com.p2p-password-manager.pinset",
        format!("kek-{store_id_hex}").as_ref(),
    )
    .with_label(format!("Pinset KEK ({})", &store_id_hex[..8]))
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
    assert_eq!(attrs.description, Some("Test key".to_string()));
}

#[test]
fn test_secure_key_creation() {
    let data = vec![1, 2, 3, 4, 5];
    let key = SecureKey::new(data.clone());

    assert_eq!(key.as_bytes(), &data[..]);
    assert_eq!(key.len(), 5);
    assert!(!key.is_empty());
}

#[test]
fn test_secure_key_debug() {
    let key = SecureKey::new(vec![1, 2, 3, 4, 5]);
    let debug_str = format!("{key:?}");
    assert!(debug_str.contains("REDACTED"));
    assert!(debug_str.contains("5 bytes"));
    // Ensure actual data is not in debug output
    assert!(!debug_str.contains("1"));
}

#[test]
fn test_secure_key_from_vec() {
    let data = vec![1, 2, 3];
    let key: SecureKey = data.clone().into();
    assert_eq!(key.as_bytes(), &data[..]);
}

#[test]
fn test_secure_key_from_slice() {
    let data: &[u8] = &[1, 2, 3, 4];
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
    let key = SecureKey::new(test_data.clone());

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
    let key = SecureKey::new(vec![1, 2, 3]);
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
    let key1 = SecureKey::new(vec![1, 2, 3]);
    let attributes = KeyAttributes::new(identifier.clone());
    keychain
        .store_key(key1, attributes.clone())
        .expect("Failed to store key");

    // Update with new data
    let key2 = SecureKey::new(vec![4, 5, 6]);
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
    let key1 = SecureKey::new(vec![1, 2, 3]);
    let attributes = KeyAttributes::new(identifier.clone());
    keychain
        .store_key(key1, attributes.clone())
        .expect("Failed to store first key");

    // Try to store again with same identifier
    let key2 = SecureKey::new(vec![4, 5, 6]);
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
    let key = SecureKey::new(vec![1, 2, 3]);
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
    let key = SecureKey::new(binary_data.clone());

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
