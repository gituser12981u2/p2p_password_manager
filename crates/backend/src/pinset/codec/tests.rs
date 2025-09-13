use std::io::Cursor;

use crate::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, PinsetError, PinsetFlags, PinsetHeader, PinsetRecord,
};

#[test]
fn round_trip_streaming() {
    let version = 1;
    let store_id = [0u8; 16];
    let nonce = [0u8; 12];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
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
    let store_id = [0u8; 16];
    let nonce = [0u8; 12];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        nonce,
    )
    .build()
    .unwrap();
    let bytes = header.encode().expect("encode");
    let read_back = PinsetHeader::from_reader(Cursor::new(&bytes)).expect("from_reader");
    assert_eq!(read_back, header)
}

#[test]
fn header_tlv_round_trip_all_fields() {
    let version = 1;
    let store_id = [0u8; 16];
    let nonce = [0u8; 12];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        nonce,
    )
    .kdf("pbkdf2".to_string())
    .kek_locator("keychain:password_manager".to_string())
    .wrap(vec![0xde, 0xad, 0xbe, 0xef])
    .build()
    .expect("build");

    let mut buf = Vec::new();
    header.write_to(&mut buf).expect("encode");

    let round = PinsetHeader::from_reader(Cursor::new(&buf)).expect("decode");
    assert_eq!(round.version, 1);
    assert_eq!(round.aead_alg as u8, header.aead_alg as u8);
    assert_eq!(round.key_source as u8, header.key_source as u8);
    assert_eq!(round.store_id, header.store_id);
    assert_eq!(round.nonce, header.nonce);
    assert_eq!(round.kdf.as_deref(), Some("pbkdf2"));
    assert_eq!(
        round.kek_locator.as_deref(),
        Some("keychain:password_manager")
    );
    assert_eq!(
        round.wrap.as_deref().map(|b| b.as_ref()),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );
}

#[test]
fn header_tlv_round_trip_no_optionals() {
    let version = 1;
    let store_id = [0u8; 16];
    let nonce = [0u8; 12];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        nonce,
    )
    .build()
    .expect("build");

    let mut buf = Vec::new();
    header.write_to(&mut buf).expect("encode");
    let round = PinsetHeader::from_reader(Cursor::new(&buf)).expect("decode");

    assert_eq!(round.version, 1);
    assert!(round.kdf.is_none());
    assert!(round.kek_locator.is_none());
    assert!(round.wrap.is_none());
}

#[test]
fn header_tlv_unknown_tag_error() {
    let version = 1;
    let store_id = [0u8; 16];
    let nonce = [0u8; 12];
    let header = PinsetHeader::builder(
        version,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        nonce,
    )
    .build()
    .expect("build");

    let buf = header.encode().expect("encode");

    assert_eq!(buf.last().copied(), Some(0x7F));
    let end_pos = buf.len() - 1;

    // Insert an unknown TLV before END: tag=0x55, len=0003, val=0x02 0x02 0x03
    let mut injected = Vec::with_capacity(buf.len() + 1 + 2 + 3);
    injected.extend_from_slice(&buf[..end_pos]);
    injected.push(0x55);
    injected.extend_from_slice(&(3u16.to_be_bytes()));
    injected.extend_from_slice(&[0x01, 0x02, 0x03]);
    injected.push(0x7F);

    let err = PinsetHeader::from_reader(Cursor::new(&injected)).unwrap_err();
    match err {
        PinsetError::Invalid(msg) => assert!(msg.contains("unknown")),
        _ => panic!("expected Invalid(..) for unknown tlv tag, got {:?}", err),
    }
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
        PinsetFlags::ACTIVE,
    )
    .with_expiration(later);

    // rest round-trip  serialisation protocol
    let bytes = record.encode().expect("encode record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode record");

    assert_eq!(decoded.peer_id, record.peer_id);
    assert_eq!(decoded.key_type, record.key_type);
    assert_eq!(decoded.key_data, record.key_data);
    // assert_eq!(decoded.key_data, record.key_data);
    assert_eq!(decoded.added_at.timestamp(), record.added_at.timestamp());
    assert_eq!(
        decoded.expires_at.map(|dt| dt.timestamp()),
        record.expires_at.map(|dt| dt.timestamp())
    );
    assert!(matches!(decoded.flags, PinsetFlags::ACTIVE));

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
        PinsetFlags::RETIRED,
    );

    // check serialisation without expiration
    let bytes = record.encode().expect("encode record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode record");

    assert_eq!(decoded.peer_id, record.peer_id);
    assert_eq!(decoded.key_type, record.key_type);
    assert_eq!(decoded.key_data, record.key_data);
    assert_eq!(decoded.added_at.timestamp(), record.added_at.timestamp());
    assert_eq!(decoded.expires_at, None);
    assert!(matches!(decoded.flags, PinsetFlags::RETIRED));

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
        PinsetFlags::TOFU,
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
    assert!(matches!(decoded.flags, PinsetFlags::TOFU));
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
        PinsetFlags::ACTIVE,
    );

    // serialisation and deserialisation with large data
    let bytes = record.encode().expect("encode large record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode large record");

    assert_eq!(decoded.peer_id, large_peer_id);
    assert_eq!(&**decoded.key_data, large_key_data);
    assert_eq!(decoded.key_type, KeyType::Spki);
    assert!(matches!(decoded.flags, PinsetFlags::ACTIVE));
}

#[test]
fn empty_data_serialisation() {
    use chrono::Utc;

    let now = Utc::now();

    // test with empty peer_id and key_data
    let record = PinsetRecord::new(vec![], KeyType::Ed25519, vec![], now, PinsetFlags::ACTIVE);

    let bytes = record.encode().expect("encode empty record");
    let decoded = PinsetRecord::from_reader(Cursor::new(&bytes)).expect("decode empty record");

    assert_eq!(decoded.peer_id, vec![]);
    assert_eq!(&**decoded.key_data, &[]);
    assert_eq!(decoded.key_type, KeyType::Ed25519);
    assert!(matches!(decoded.flags, PinsetFlags::ACTIVE));
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
