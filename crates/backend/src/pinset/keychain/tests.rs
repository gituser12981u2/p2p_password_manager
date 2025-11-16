// TODO: Gate Tests
// #![cfg(feature = "os-keychain-tests")]
#![cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]

use crate::pinset::keychain::{
    KeyAttributes, KeyIdentifier, Keychain, KeychainError, SecureKey, default_keychain,
    kek_identifier_for_store,
};
use serial_test::serial;

fn unique_id(prefix: &str) -> KeyIdentifier {
    use rand::{Rng, distributions::Alphanumeric};
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    KeyIdentifier::new(
        "com.p2p-password-manager.test".to_string(),
        format!("{prefix}-{}-{suffix}", std::process::id()),
    )
}

#[test]
#[serial]
fn raw_bytes_round_trip_including_nul_and_non_utf8() {
    let kc = match Keychain::new() {
        Ok(k) => k,
        Err(_) => return,
    };

    let id = unique_id("raw-roundtrip");
    let attrs = KeyAttributes::new(id.clone());

    // Clean up
    let _ = kc.delete_key(&id);

    // Includes NULs and non-UTF-8
    let data = vec![0x00, 0xff, 0x01, 0x00, 0xfe, 0x7f, 0x80, 0xc3, 0x28];
    let key = SecureKey::from(data.clone());

    kc.store_key(key, attrs).expect("store raw key");

    let out = kc.retrieve_key(&id).expect("retrieve raw key");
    assert_eq!(out.as_bytes(), &data[..]);

    let _ = kc.delete_key(&id);
}

#[test]
#[serial]
fn update_preserves_raw_bytes() {
    let kc = Keychain::new().unwrap();
    let id = unique_id("raw-update");
    let attrs = KeyAttributes::new(id.clone());
    let _ = kc.delete_key(&id);

    let v1 = vec![0x00, 0x01, 0xff];
    kc.store_key(SecureKey::from(v1.clone()), attrs.clone())
        .unwrap();

    let v2 = vec![0xaa, 0xbb, 0x00, 0xcc];
    kc.update_key(SecureKey::from(v2.clone()), attrs).unwrap();

    let out = kc.retrieve_key(&id).unwrap();
    assert_eq!(out.as_bytes(), &v2[..]);

    let _ = kc.delete_key(&id);
}

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
