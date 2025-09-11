use crate::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, PinsetFlags, PinsetHeader, PinsetRecord,
};
use std::io::Cursor;

#[test]
fn pinset_record_is_active() {
    use chrono::Utc;

    let now = Utc::now();

    let active_record = PinsetRecord::new(
        b"active_peer".to_vec(),
        KeyType::Ed25519,
        b"key".to_vec(),
        now,
        PinsetFlags::Active,
    );

    let retired_record = PinsetRecord::new(
        b"retired_peer".to_vec(),
        KeyType::Ed25519,
        b"key".to_vec(),
        now,
        PinsetFlags::Retired,
    );

    let tofu_record = PinsetRecord::new(
        b"tofu_peer".to_vec(),
        KeyType::Ed25519,
        b"key".to_vec(),
        now,
        PinsetFlags::Tofu,
    );

    assert!(active_record.is_active());
    assert!(!retired_record.is_active());
    assert!(!tofu_record.is_active());
}

#[test]
fn pinset_header_validation() {
    // test for valid header format.
    let valid_nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];
    let store_id = [0u8; 16];
    let _valid_header = PinsetHeader::builder(
        1,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        valid_nonce,
    )
    .build()
    .expect("valid header should build");

    let invalid_version = PinsetHeader {
        version: 0,
        aead_alg: AeadAlgorithm::AesGcm,
        key_source: KeySource::OsKeyStore,
        kdf: None,
        kek_locator: None,
        store_id,
        seq: 0,
        nonce: vec![0u8; 12],
        wrap: None,
    };
    assert!(invalid_version.validate().is_err());

    // test for invalid nonce length
    let invalid_nonce = PinsetHeader {
        version: 1,
        aead_alg: AeadAlgorithm::AesGcm,
        key_source: KeySource::OsKeyStore,
        kdf: None,
        kek_locator: None,
        store_id,
        seq: 0,
        nonce: vec![0u8; 10], // invalid length for AES-GCM
        wrap: None,
    };
    assert!(invalid_nonce.validate().is_err());
}

#[test]
fn pinset_header_builder_patterns() {
    let nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];
    let store_id = [0u8; 16];

    // test builder with all optional fields
    let header = PinsetHeader::builder(
        2,
        AeadAlgorithm::AesGcm,
        KeySource::PassphraseKdf,
        store_id,
        nonce,
    )
    .kdf("pbkdf2".to_string())
    .kek_locator("keychain:password_manager".to_string())
    .seq(42)
    .wrap(vec![0xde, 0xad, 0xbe, 0xef])
    .build()
    .expect("complex header should build");

    assert_eq!(header.version, 2);
    assert_eq!(header.aead_alg, AeadAlgorithm::AesGcm);
    assert_eq!(header.key_source, KeySource::PassphraseKdf);
    assert_eq!(header.kdf, Some("pbkdf2".to_string()));
    assert_eq!(
        header.kek_locator,
        Some("keychain:password_manager".to_string())
    );
    assert_eq!(header.seq, 42);
    assert_eq!(
        header.wrap.as_deref().map(|v| v.as_ref()),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );
}

#[test]
fn aead_algorithm_nonce_lengths() {
    assert_eq!(AeadAlgorithm::AesGcm.nonce_len(), 12);
}

#[test]
fn datetime_edge_cases() {
    use chrono::DateTime;

    // Test with Unix epoch
    let epoch = DateTime::from_timestamp(0, 0).unwrap();

    let record = PinsetRecord::new(
        b"epoch_peer".to_vec(),
        KeyType::Ed25519,
        b"key".to_vec(),
        epoch,
        PinsetFlags::Active,
    )
    .with_expiration(DateTime::from_timestamp(1, 0).unwrap());

    let bytes = record.encode().expect("encode epoch record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode epoch record");

    assert_eq!(decoded.added_at.timestamp(), 0);
    assert_eq!(decoded.expires_at.unwrap().timestamp(), 1);

    //  test expiration logic with epoch times
    let before_epoch = DateTime::from_timestamp(-1, 0).unwrap();
    let after_expiration = DateTime::from_timestamp(2, 0).unwrap();

    assert!(!record.is_expired(before_epoch)); // before expiration
    assert!(record.is_expired(after_expiration)); // after expiration
}
