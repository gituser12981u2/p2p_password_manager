/// Integration test for PinsetStore.
///
/// This verifies that:
/// - A store created via `PinsetStore::create_os_keystore` writes a valid header.
/// - The header `kek_locator` matches the derived KEK identifier (service/account).
/// - Records can be added, saved, and reopened via `PinsetStore::open`.
/// - The ciphertext on disk does not contain the plaintext key bytes.
/// - Removing the KEK from the OS keychain makes the store unreadable.
use backend::pinset::{
    keychain::{KeyIdentifier, KeychainError, default_keychain, kek_identifier_for_store},
    store::{PinsetStore, PinsetStoreError},
    types::{AeadAlgorithm, KeySource, KeyType, PinsetFlags, PinsetHeader, PinsetRecord},
};
use chrono::Utc;
use rand::RngCore;
use serial_test::serial;
use std::{
    fs::{self, File},
    io::Read,
    time::UNIX_EPOCH,
};

fn temp_store_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "pinset_store_os_keystore_{}_{}.pset",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ))
}

fn read_header_from(path: &std::path::Path) -> PinsetHeader {
    let mut f = File::open(path).expect("Failed to open store file for header read");
    PinsetHeader::read_tlv(&mut f).expect("Failed to decode header")
}

#[test]
#[serial]
fn test_os_keystore_header_and_kek_locator() {
    let temp_path = temp_store_path();
    let keychain = default_keychain().expect("Failed to create keychain");

    PinsetStore::create_os_keystore(&temp_path).expect("Failed to create OS keystore");

    // Read header
    let header = read_header_from(&temp_path);
    assert_eq!(header.version, 1);
    assert_eq!(header.aead_alg, AeadAlgorithm::AesGcm);
    assert_eq!(header.key_source, KeySource::OsKeyStore);
    assert!(
        header.seq > 0,
        "Initial seq should be greater than 0 after first save"
    );

    // Set kek_locator
    let locator = header
        .kek_locator
        .as_ref()
        .expect("kek_locator should be present for OS keystore stores");
    let locator_str = locator
        .to_str()
        .expect("kek_locator should be valid UTF-8")
        .to_owned();

    // Parse kek_locator
    let (service, account) = locator_str
        .split_once('/')
        .expect("kek_locator must be in the form 'service/account'");
    let locator_id = KeyIdentifier::new(service, account);

    // TODO, remember to change these functions names to either be better or more specific, like store->pinsetstore

    // Derived KEK identifier from store_id should match the locator-derived identifier
    let derived_id = kek_identifier_for_store(&header.store_id);
    assert_eq!(
        locator_id.service, derived_id.service,
        "kek_locator service must match kek_identifier_for_store(store_id) service"
    );
    assert_eq!(
        locator_id.account, derived_id.account,
        "kek_locator account must match kek_identifier_for_store(store_id) account"
    );

    // Check that identifier exists in the OS keystore
    let exists = keychain
        .key_exists(&locator_id)
        .expect("key_exists check should succeed");
    assert!(
        exists,
        "KEK reference by kek_locator should exist in OS keychain after storing"
    );

    let _ = fs::remove_file(&temp_path);
}

#[test]
#[serial]
fn test_pinset_store_record_roundtrip_and_ciphertext() {
    let temp_path = temp_store_path();

    let mut store =
        PinsetStore::create_os_keystore(&temp_path).expect("Failed to create OS keystore");
    let header = read_header_from(&temp_path);
    let seq_after_create = header.seq;

    let mut peer_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut peer_id);

    let key_bytes = b"test_key_data_for_pinset_store".to_vec();
    let record = PinsetRecord::new(
        peer_id,
        KeyType::Ed25519,
        key_bytes.clone(),
        Utc::now(),
        PinsetFlags::ACTIVE,
    );

    store.add_record(record.clone());
    store
        .save()
        .expect("Failed to save store after adding record");

    // Re-read header
    let mut f2 = File::open(&temp_path).expect("Failed to reopen store file");
    let header2 =
        PinsetHeader::read_tlv(&mut f2).expect("Failed to decode header after save with record");
    assert_eq!(
        header2.store_id, header.store_id,
        "store_id must be stable across saves"
    );
    assert_eq!(
        header2.kek_locator, header.kek_locator,
        "kek_locator must be stable across saves"
    );
    assert_eq!(
        header2.seq,
        seq_after_create.wrapping_add(1),
        "seq must bump by 1 on each successful save"
    );

    // Read the ciphertext body
    let mut ciphertext = Vec::new();
    f2.read_to_end(&mut ciphertext)
        .expect("Failed to read ciphertext body");
    assert!(
        !ciphertext.is_empty(),
        "Ciphertext body should not be empty after adding a record"
    );

    // Check ciphertext does not contain plaintext
    assert!(
        !ciphertext
            .windows(key_bytes.len())
            .any(|w| w == &key_bytes[..]),
        "Ciphertext should not contain the plaintext key bytes"
    );

    // Verify record roundtrip via high level API
    let reopened =
        PinsetStore::open(&temp_path, None).expect("Failed to reopen store via PinsetStore::open");
    assert_eq!(
        reopened.records().len(),
        1,
        "Reopened store should contain exactly one record"
    );

    let reopened_record = &reopened.records()[0];
    assert_eq!(reopened_record.peer_id, record.peer_id);
    assert_eq!(reopened_record.key_type, record.key_type);
    assert_eq!(
        reopened_record.flags, record.flags,
        "Flags should round-trip correctly"
    );
    assert_eq!(
        &*reopened_record.key_data, &*record.key_data,
        "key_data should round-trip correctly through encryption/decryption"
    );
}

#[test]
#[serial]
fn test_open_fails_after_kek_deleted() {
    let temp_path = temp_store_path();
    let keychain = default_keychain().expect("Failed to create keychain");

    {
        let mut store =
            PinsetStore::create_os_keystore(&temp_path).expect("Failed to create OS keystore");

        let mut peer_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut peer_id);

        let record = PinsetRecord::new(
            peer_id,
            KeyType::Ed25519,
            vec![1, 2, 3],
            Utc::now(),
            PinsetFlags::ACTIVE,
        );

        store.add_record(record.clone());
        store
            .save()
            .expect("Failed to save store after adding record");
    }
    let header = read_header_from(&temp_path);
    let derived_id = kek_identifier_for_store(&header.store_id);

    // Delete the KEK from the keychain, then attempt to open should fail
    keychain
        .delete_key(&derived_id)
        .expect("Failed to delete KEK from keychain for negative test");

    let reopened_err = PinsetStore::open(&temp_path, None);
    assert!(
        reopened_err.is_err(),
        "Opening a store after deleting its KEK must fail"
    );

    match reopened_err.unwrap_err() {
        PinsetStoreError::Keychain(KeychainError::NotFound(_)) => {}
        other => panic!("Expected Keychain::NotFound error, got: {other:?}"),
    }

    let _ = fs::remove_file(&temp_path);
}
