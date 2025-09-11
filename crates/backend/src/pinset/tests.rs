use crate::pinset::types::{
    AeadAlgorithm, GenericArray, KeySource, KeyType, PinsetFlags, PinsetHeader, PinsetRecord,
};
use std::io::Cursor;

#[test]
fn round_trip_streaming() {
    let version = 1;
    let store_id = b"store-01";
    let nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id.to_vec(),
        nonce,
    )
    .build()
    .unwrap();
    let mut buf = Vec::new();

    // write/read via streaming API
    header.write_to(&mut buf).expect("write_to");
    let read_back = PinsetHeader::from_reader(Cursor::new(&buf)).expect("from_reader");
    assert_eq!(read_back, header);
}

#[test]
fn round_trip_buffered() {
    let version = 1;
    let store_id = b"store-01";
    let nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id.to_vec(),
        nonce,
    )
    .build()
    .unwrap();
    let bytes = header.encode().expect("encode");
    let read_back = PinsetHeader::from_reader(Cursor::new(&bytes)).expect("from_reader");
    assert_eq!(read_back, header)
}

#[test]
fn pinset_record_round_trip() {
    use chrono::Utc;

    let now = Utc::now();
    let later = now + chrono::Duration::hours(1);

    let record = PinsetRecord::new(
        b"peer123".to_vec(),
        KeyType::Ed25519,
        b"keydata".to_vec(),
        now,
        PinsetFlags::Active,
    )
    .with_expiration(later);

    // rest round-trip  serialisation protocol
    let bytes = record.encode().expect("encode record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode record");

    assert_eq!(decoded.peer_id, record.peer_id);
    assert_eq!(decoded.key_type, record.key_type);
    assert_eq!(decoded.key_data, record.key_data);
    assert_eq!(decoded.added_at.timestamp(), record.added_at.timestamp());
    assert_eq!(
        decoded.expires_at.map(|dt| dt.timestamp()),
        record.expires_at.map(|dt| dt.timestamp())
    );
    assert!(matches!(decoded.flags, PinsetFlags::Active));

    // Test is_expired functionality
    let past = now - chrono::Duration::hours(1);
    let future = now + chrono::Duration::hours(2);

    assert!(!record.is_expired(past)); // Not expired when current time is before expiration
    assert!(record.is_expired(future)); // Expired when current time is after expiration
}

#[test]
fn pinset_record_no_expiration() {
    use chrono::Utc;

    let now = Utc::now();
    let record = PinsetRecord::new(
        b"peer456".to_vec(),
        KeyType::Spki,
        b"spki_key_data".to_vec(),
        now,
        PinsetFlags::Retired,
    );

    // check serialisation without expiration
    let bytes = record.encode().expect("encode record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode record");

    assert_eq!(decoded.peer_id, record.peer_id);
    assert_eq!(decoded.key_type, record.key_type);
    assert_eq!(decoded.key_data, record.key_data);
    assert_eq!(decoded.added_at.timestamp(), record.added_at.timestamp());
    assert_eq!(decoded.expires_at, None);
    assert!(matches!(decoded.flags, PinsetFlags::Retired));

    // check that record never expires when no expiration is set
    let future = now + chrono::Duration::days(365);
    assert!(!record.is_expired(future));
}

#[test]
fn pinset_record_pq_hybrid_tofu() {
    use chrono::Utc;

    let now = Utc::now();
    let expires = now + chrono::Duration::minutes(30);

    let record = PinsetRecord::new(
        b"pq_peer".to_vec(),
        KeyType::PqHybrid,
        vec![0x42; 100], // Large key data
        now,
        PinsetFlags::Tofu,
    )
    .with_expiration(expires);

    // test round-trip with PQ hybrid and TOFU flags
    let bytes = record.encode().expect("encode record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode record");

    assert_eq!(decoded.peer_id, record.peer_id);
    assert_eq!(decoded.key_type, record.key_type);
    assert_eq!(decoded.key_data, record.key_data);
    assert_eq!(decoded.added_at.timestamp(), record.added_at.timestamp());
    assert_eq!(
        decoded.expires_at.map(|dt| dt.timestamp()),
        record.expires_at.map(|dt| dt.timestamp())
    );
    assert!(matches!(decoded.flags, PinsetFlags::Tofu));
}

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
    let _valid_header = PinsetHeader::builder(
        1,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        b"store123".to_vec(),
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
        store_id: b"store".into(),
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
        store_id: b"store".to_vec(),
        seq: 0,
        nonce: vec![0u8; 10], // invalid length for AES-GCM
        wrap: None,
    };
    assert!(invalid_nonce.validate().is_err());
}

#[test]
fn pinset_header_builder_patterns() {
    let nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];

    // test builder with all optional fields
    let header = PinsetHeader::builder(
        2,
        AeadAlgorithm::AesGcm,
        KeySource::PassphraseKdf,
        b"complex_store".to_vec(),
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
    assert_eq!(header.wrap, Some(vec![0xde, 0xad, 0xbe, 0xef]));
}

#[test]
fn aead_algorithm_nonce_lengths() {
    assert_eq!(AeadAlgorithm::AesGcm.nonce_len(), 12);
}

#[test]
fn large_data_serialisation() {
    use chrono::Utc;

    let now = Utc::now();

    // test with maximum size data
    let large_peer_id = vec![0x55; u16::MAX as usize];
    let large_key_data = vec![0xAA; u16::MAX as usize];

    let record = PinsetRecord::new(
        large_peer_id.clone(),
        KeyType::Spki,
        large_key_data.clone(),
        now,
        PinsetFlags::Active,
    );

    // serialisation and deserialisation with large data
    let bytes = record.encode().expect("encode large record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode large record");

    assert_eq!(decoded.peer_id, large_peer_id);
    assert_eq!(decoded.key_data, large_key_data);
    assert_eq!(decoded.key_type, KeyType::Spki);
    assert!(matches!(decoded.flags, PinsetFlags::Active));
}

#[test]
fn empty_data_serialisation() {
    use chrono::Utc;

    let now = Utc::now();

    // test with empty peer_id and key_data
    let record = PinsetRecord::new(vec![], KeyType::Ed25519, vec![], now, PinsetFlags::Active);

    let bytes = record.encode().expect("encode empty record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode empty record");

    assert_eq!(decoded.peer_id, vec![]);
    assert_eq!(decoded.key_data, vec![]);
    assert_eq!(decoded.key_type, KeyType::Ed25519);
    assert!(matches!(decoded.flags, PinsetFlags::Active));
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

#[test]
fn error_handling_invalid_data() {
    let truncated_data = vec![0x00, 0x01]; // Only 2 bytes
    let result = PinsetRecord::from_reader(Cursor::new(truncated_data));
    assert!(result.is_err());

    // Test with invalid key type
    let invalid_key_type_data = vec![
        0x00, 0x04, b'p', b'e', b'e', b'r', // peer_id_len + peer_id
        0xFF, // Invalid key type
    ];
    let result = PinsetRecord::from_reader(Cursor::new(invalid_key_type_data));
    assert!(result.is_err());

    // Test with invalid flags
    let mut valid_data = vec![
        0x00, 0x04, b'p', b'e', b'e', b'r', // peer_id_len + peer_id
        0x01, // Ed25519 key type
        0x00, 0x03, b'k', b'e', b'y', // key_len + key_data
    ];
    valid_data.extend_from_slice(&1i64.to_be_bytes()); // added_at timestamp
    valid_data.push(0x00); // has_expires = false
    valid_data.push(0xFF); // Invalid flags value

    let result = PinsetRecord::from_reader(Cursor::new(valid_data));
    assert!(result.is_err());
}

#[test]
fn generic_array_functionality() {
 
    let mut arr: GenericArray<10> = GenericArray::new();
    assert_eq!(arr.len(), 0);
    assert_eq!(arr.capacity(), 10);

    arr.push(b'h').expect("push h");
    arr.push(b'i').expect("push i");
    assert_eq!(arr.len(), 2);

    assert_eq!(arr.get(0).expect("get 0"), b'h');
    assert_eq!(arr.get(1).expect("get 1"), b'i');
    assert!(arr.get(2).is_err()); // Out of bounds

    assert_eq!(arr[0], b'h');
    assert_eq!(arr[1], b'i');


    let str_arr = GenericArray::<10>::try_from_bytes("test").expect("from_str");
    assert_eq!(str_arr.as_str().expect("as_str"), "test");
    assert_eq!(str_arr.len(), 4);

    // buffer full too long
    let result = GenericArray::<3>::try_from_bytes("toolong");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        crate::pinset::types::PinsetError::BufferFull(3)
    ));
}
