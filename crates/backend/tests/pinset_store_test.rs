/// Integration test for PinsetStore.
///
/// This verifies that:
/// - A store created via `PinsetStore::create_os_keystore` writes a valid header.
/// - Records can be added, saved, and reopened via `PinsetStore::open`.
/// - The ciphertext on disk does not contain the plaintext key bytes.
use backend::pinset::{
    store::PinsetStore,
    types::{KeyType, PinsetFlags, PinsetHeader, PinsetRecord},
};
use chrono::Utc;
use rand::RngCore;
use serial_test::serial;
use std::{fs::File, io::Read, time::UNIX_EPOCH};

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
    let mut f = File::open(&temp_path).expect("Failed to reopen store file");
    let header2 =
        PinsetHeader::read_tlv(&mut f).expect("Failed to decode header after save with record");
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
    f.read_to_end(&mut ciphertext)
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
