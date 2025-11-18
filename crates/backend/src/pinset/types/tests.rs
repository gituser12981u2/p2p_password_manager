use chrono::Utc;

use crate::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, PinsetFlags, PinsetHeader, PinsetRecord, decode_body,
    encode_body,
};
use std::ffi::OsStr;
use std::io::Cursor;

#[test]
fn header_tlv_roundtrip() {
    let header = PinsetHeader::builder(
        1,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        [1u8; 16],
        [2u8; 12],
    )
    .kek_locator("com.example/service")
    .seq(42) // The answer to life
    .build()
    .unwrap();

    let bytes = header.encode_tlv().unwrap();
    let decoded = PinsetHeader::decode_tlv(&bytes).unwrap();
    assert_eq!(decoded, header);
}

#[test]
fn body_encode_decode_roundtrip() {
    let now = Utc::now();
    let records = vec![
        PinsetRecord::new(
            [1u8; 32],
            KeyType::Ed25519,
            vec![1, 2],
            now,
            PinsetFlags::ACTIVE,
        ),
        PinsetRecord::new(
            [2u8; 32],
            KeyType::Spki,
            vec![3, 4],
            now,
            PinsetFlags::RETIRED,
        ),
    ];

    let body = encode_body(&records).unwrap();
    let decoded = decode_body(&body).unwrap();

    assert_eq!(decoded.len(), records.len());
    for (a, b) in decoded.iter().zip(records.iter()) {
        assert_eq!(a.peer_id, b.peer_id);
        assert_eq!(a.peer_id, b.peer_id);
        assert_eq!(a.key_type, b.key_type);
        assert_eq!(a.flags, b.flags);
        assert_eq!(&*a.key_data, &*b.key_data);
    }
}

#[test]
fn record_tlv_roundtrip() {
    let record = PinsetRecord::new(
        [3u8; 32],
        KeyType::Ed25519,
        b"hello".to_vec(),
        Utc::now(),
        PinsetFlags::ACTIVE,
    );
    let bytes = record.encode_tlv().unwrap();
    let decoded = PinsetRecord::decode_tlv(&bytes).unwrap();

    assert_eq!(decoded.peer_id, record.peer_id);
    assert_eq!(decoded.key_type, record.key_type);
    assert_eq!(decoded.flags, record.flags);
    assert_eq!(&*decoded.key_data, &*record.key_data);
}

#[test]
fn pinset_record_is_active() {
    use chrono::Utc;

    let now = Utc::now();

    let mut active_peer_id = [0u8; 32];
    active_peer_id[..11].copy_from_slice(b"active_peer");
    let active_record = PinsetRecord::new(
        active_peer_id,
        KeyType::Ed25519,
        b"key".to_vec(),
        now,
        PinsetFlags::ACTIVE,
    );

    let mut retired_peer_id = [0u8; 32];
    retired_peer_id[..12].copy_from_slice(b"retired_peer");
    let retired_record = PinsetRecord::new(
        retired_peer_id,
        KeyType::Ed25519,
        b"key".to_vec(),
        now,
        PinsetFlags::RETIRED,
    );

    let mut tofu_peer_id = [0u8; 32];
    tofu_peer_id[..9].copy_from_slice(b"tofu_peer");
    let tofu_record = PinsetRecord::new(
        tofu_peer_id,
        KeyType::Ed25519,
        b"key".to_vec(),
        now,
        PinsetFlags::TOFU,
    );

    assert!(active_record.is_active());
    assert!(!retired_record.is_active());
    assert!(!tofu_record.is_active());
}

#[test]
fn pinset_header_validation() {
    // test for valid header format.
    let valid_nonce = [0u8; 12];
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
        nonce: [0u8; 12],
        wrap: None,
    };
    assert!(invalid_version.validate().is_err());
}

#[test]
fn pinset_header_builder_patterns() {
    let nonce = [0u8; 12];
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
    .kek_locator("keychain:password_manager")
    .seq(42)
    .wrap(vec![0xde, 0xad, 0xbe, 0xef])
    .build()
    .expect("complex header should build");

    assert_eq!(header.version, 2);
    assert_eq!(header.aead_alg, AeadAlgorithm::AesGcm);
    assert_eq!(header.key_source, KeySource::PassphraseKdf);
    assert_eq!(header.kdf.as_deref(), Some("pbkdf2"));
    assert_eq!(
        header.kek_locator.as_deref(),
        Some(OsStr::new("keychain:password_manager"))
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

    let mut epoch_peer_id = [0u8; 32];
    epoch_peer_id[..10].copy_from_slice(b"epoch_peer");
    let record = PinsetRecord::new(
        epoch_peer_id,
        KeyType::Ed25519,
        b"key".to_vec(),
        epoch,
        PinsetFlags::ACTIVE,
    )
    .with_expiration(DateTime::from_timestamp(1, 0).unwrap());

    let bytes = record.encode_tlv().expect("encode epoch record");
    let decoded = PinsetRecord::read_tlv(Cursor::new(&bytes)).expect("decode epoch record");

    assert_eq!(decoded.added_at.timestamp(), 0);
    assert_eq!(decoded.expires_at.unwrap().timestamp(), 1);

    //  test expiration logic with epoch times
    let before_epoch = DateTime::from_timestamp(-1, 0).unwrap();
    let after_expiration = DateTime::from_timestamp(2, 0).unwrap();

    assert!(!record.is_expired(before_epoch)); // before expiration
    assert!(record.is_expired(after_expiration)); // after expiration
}
