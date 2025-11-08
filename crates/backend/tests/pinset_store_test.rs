
/*

All this test does is verify that data is kept in the proper format when encrypting and decrypting.

*/

use backend::pinset::{
    keychain::{default_keychain, KeyAttributes, SecureKey},
    types::{AeadAlgorithm, KeySource, KeyType, PinsetFlags, PinsetHeader, PinsetRecord},
};
use chrono::Utc;
use rand::RngCore;
use serial_test::serial;
use std::fs;

#[test]
#[serial]
fn test_pinset_store_with_os_keystore_integration() {
  
    let keychain = default_keychain().expect("Failed to create keychain");
    
    // random store ID to avoid conflicts across test runs
    let mut store_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut store_id);
    
    //unique identifier for our KEK in the OS keychain
    let kek_identifier = backend::pinset::keychain::kek_identifier_for_store(&store_id);
    
    // remove up any existing test key first
    let _ = keychain.delete_key(&kek_identifier);
    
    // create a KEK that will be stored in OS keychain
    let mut kek_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut kek_bytes);
    let kek = SecureKey::from(kek_bytes.clone());
    
    // put KEK in the OS keychain
    let kek_attributes = KeyAttributes::new(kek_identifier.clone());
    let store_result = keychain.store_key(kek, kek_attributes);
    assert!(
        store_result.is_ok(),
        "Failed to store KEK in OS keychain: {:?}",
        store_result.err()
    );

    let exists_result = keychain.key_exists(&kek_identifier);
    assert!(
        exists_result.is_ok() && exists_result.unwrap(),
        "KEK should exist in OS keychain after storing"
    );
    
    // get the KEK from OS keychain to verify it can be decrypted
    let retrieved_kek_result = keychain.retrieve_key(&kek_identifier);
    assert!(
        retrieved_kek_result.is_ok(),
        "Failed to retrieve KEK from OS keychain: {:?}",
        retrieved_kek_result.err()
    );
    
    let retrieved_kek = retrieved_kek_result.unwrap();
    assert_eq!(
        retrieved_kek.as_bytes(),
        &kek_bytes[..], // compare with original
        "Retrieved KEK should match original"
    );
    
 
    let temp_path = std::env::temp_dir().join(format!("pinset_store_test_{}.pset", std::process::id()));
    
  
    let nonce = [0u8; 12]; // It's arbitrary for this use case
    let header = PinsetHeader::builder(
        1, 
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        nonce,
    )
    .kek_locator(&kek_identifier.to_unique_string())
    .build()
    .expect("Failed to build header");
 
    let validation_result = header.validate();
    assert!(
        validation_result.is_ok(),
        "Header should be valid: {:?}",
        validation_result.err()
    );
    
  
    let mut peer_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut peer_id);
    
    let record = PinsetRecord::new(
        peer_id,
        KeyType::Ed25519,
        b"test_key_data".to_vec(),
        Utc::now(),
        PinsetFlags::ACTIVE,
    );
    
    // check if record is properly formatted
    let record_bytes = record.encode().expect("Failed to encode record");
    let decoded_record = PinsetRecord::from_reader(&*record_bytes).expect("Failed to decode record");
    assert_eq!(decoded_record.peer_id, record.peer_id);
    assert_eq!(decoded_record.key_type, record.key_type);
    assert_eq!(decoded_record.key_data, record.key_data);
    assert_eq!(decoded_record.flags, record.flags);
    
    let header_bytes = header.encode().expect("Failed to encode header");
    
    // check the file format is correct by reading it back
    let mut file_data = header_bytes.clone(); // to keep original
    let record_bytes = record.encode().expect("Failed to encode record");
    file_data.extend_from_slice(&record_bytes);
    
    fs::write(&temp_path, &file_data).expect("Failed to write pinset store to file");
    
    //  check format is preserved
    let read_file_data = fs::read(&temp_path).expect("Failed to read pinset store file");
    assert_eq!(
        read_file_data.len(),
        file_data.len(),
        "File should have expected length"
    );
    
    // check that the header portion matches the expected format by reading it back
    let read_header = PinsetHeader::from_reader(&read_file_data[..header_bytes.len()])
        .expect("Failed to decode header from file");
    
    assert_eq!(read_header.version, header.version);
    assert_eq!(read_header.aead_alg, header.aead_alg);
    assert_eq!(read_header.key_source, header.key_source);
    assert_eq!(read_header.store_id, header.store_id);
    
    let _ = fs::remove_file(&temp_path);
    
    // Clean up the test key from keychain
    let delete_result = keychain.delete_key(&kek_identifier);
    assert!(
        delete_result.is_ok(),
        "Failed to delete KEK from OS keychain: {:?}",
        delete_result.err()
    );
    
}