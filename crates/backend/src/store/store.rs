use crate::pinset::types::{PinsetError, PinsetFlags, PinsetRecord, Result};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetStore {
    pub records: Vec<PinsetRecord>,
    pub version: u32,
}

impl PinsetStore {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            version: 1,
        }
    }
    /// Set a capacity to avoid reallocations
    pub fn new_with_capacity(size: usize) -> Self {
        Self {
            records: Vec::with_capacity(size),
            version: 1,
        }
    }



    pub fn find_by_peer_id(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn cleanup_expired(&mut self, current_time: DateTime<Utc>) {
        self.records.retain(|r| !r.is_expired(current_time));
        // Random comment, retain isn't *actually* performant
        //https://github.com/rust-lang/rust/issues/91497
        // I'm going to just leave this here if anyone wants to look at it (i tested this last week but it's really concise and readable for now!)
    }

    pub fn add_record(&mut self, record: PinsetRecord) {
        self.records.push(record);
    }

    pub fn remove_record(&mut self, peer_id: &[u8]) -> Option<PinsetRecord> {
        if let Some(pos) = self.records.iter().position(|r| r.peer_id == peer_id) {
            Some(self.records.remove(pos))
        } else {
            None
        }
    }

    pub fn get_record(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn get_active_records(&self) -> Vec<&PinsetRecord> {
        self.records
            .iter()
            .filter(|r| r.flags.contains(PinsetFlags::ACTIVE))
            .collect()
    }

    pub fn add_encrypted_record(&mut self, record: &PinsetRecord, key: &[u8; 32]) -> Result<()> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)); //TODO! make the encryption algorithm a generic parameter

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let serialized = record.encode()?;

        let encrypted_data = cipher
            .encrypt(&nonce, serialized.as_ref())
            .map_err(|_| PinsetError::Invalid("AES-GCM encryption failed"))?;

        let mut combined_data = Vec::with_capacity(12 + encrypted_data.len());
        combined_data.extend_from_slice(&nonce);
        combined_data.extend_from_slice(&encrypted_data);

        let mut encrypted_record = record.clone();
        encrypted_record.key_data = zeroize::Zeroizing::from(combined_data.into_boxed_slice());

        self.records.push(encrypted_record);
        Ok(())
    }
    // This should be parameterised by type ie, once we use more than aes256gcm
    //  pub fn get_encrypted_record<Algo:T>(...) etc
    pub fn get_encrypted_record(
        &self,
        peer_id: &[u8],
        key: &[u8; 32],
    ) -> Result<Option<PinsetRecord>> {
        if let Some(encrypted_record) = self.get_record(peer_id) {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

            if encrypted_record.key_data.len() < 12 {
                return Err(PinsetError::Invalid("Invalid encrypted data: too short"));
            }

            let (nonce_bytes, ciphertext) = encrypted_record.key_data.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            let decrypted_data = cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| PinsetError::Invalid("AES-GCM decryption failed"))?;

            let decrypted_record = PinsetRecord::decode(&decrypted_data)?;
            Ok(Some(decrypted_record))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pinset::types::{KeyType, PinsetFlags};
    use chrono::Utc;

    fn create_test_record() -> PinsetRecord {
        let mut peer_id = [0u8; 32];
        peer_id[..10].copy_from_slice(b"test_peer1");

        PinsetRecord::new(
            peer_id,
            KeyType::Ed25519,
            b"test_key_data_123".to_vec(),
            Utc::now(),
            PinsetFlags::ACTIVE,
        )
    }

    fn create_test_key() -> [u8; 32] {
        [0x42; 32] // Simple test key
    }

    #[test]
    fn test_add_encrypted_record_success() {
        let mut store = PinsetStore::new();
        let record = create_test_record();
        let key = create_test_key();

        let result = store.add_encrypted_record(&record, &key);
        assert!(result.is_ok());
        assert_eq!(store.records.len(), 1);

        // Verify the encrypted record has the same peer_id but different key_data
        let encrypted_record = &store.records[0];
        assert_eq!(encrypted_record.peer_id, record.peer_id);
        assert_ne!(encrypted_record.key_data.as_ref(), record.key_data.as_ref());

        // Verify encrypted data contains nonce (12 bytes) + ciphertext
        assert!(encrypted_record.key_data.len() > 12);
    }

    #[test]
    fn test_get_encrypted_record_success() {
        let mut store = PinsetStore::new();
        let record = create_test_record();
        let key = create_test_key();

        // Add encrypted record
        store.add_encrypted_record(&record, &key).unwrap();

        // Retrieve and decrypt
        let result = store.get_encrypted_record(&record.peer_id, &key);
        assert!(result.is_ok());

        let decrypted = result.unwrap();
        assert!(decrypted.is_some());

        let decrypted_record = decrypted.unwrap();
        assert_eq!(decrypted_record.peer_id, record.peer_id);
        assert_eq!(decrypted_record.key_type, record.key_type);
        assert_eq!(decrypted_record.key_data.as_ref(), record.key_data.as_ref());
        assert_eq!(decrypted_record.flags, record.flags);
    }

    #[test]
    fn test_encryption_decryption_round_trip() {
        let mut store = PinsetStore::new();
        let record = create_test_record();
        let key = create_test_key();

        store.add_encrypted_record(&record, &key).unwrap();

        let decrypted = store
            .get_encrypted_record(&record.peer_id, &key)
            .unwrap()
            .unwrap();

        // Verify all fields match
        assert_eq!(decrypted.peer_id, record.peer_id);
        assert_eq!(decrypted.key_type, record.key_type);
        assert_eq!(decrypted.key_data.as_ref(), record.key_data.as_ref());
        assert_eq!(decrypted.added_at.timestamp(), record.added_at.timestamp());
        assert_eq!(decrypted.expires_at, record.expires_at);
        assert_eq!(decrypted.flags, record.flags);
    }

    #[test]
    fn test_get_encrypted_record_not_found() {
        let store = PinsetStore::new();
        let key = create_test_key();
        let peer_id = [0u8; 32];

        let result = store.get_encrypted_record(&peer_id, &key);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_encrypted_record_wrong_key() {
        let mut store = PinsetStore::new();
        let record = create_test_record();
        let correct_key = create_test_key();
        let wrong_key = [0x99; 32];

        store.add_encrypted_record(&record, &correct_key).unwrap();

       
        let result = store.get_encrypted_record(&record.peer_id, &wrong_key);
        assert!(result.is_err());

        if let Err(PinsetError::Invalid(msg)) = result {
            assert_eq!(msg, "AES-GCM decryption failed");
        } else {
            panic!("Expected PinsetError::Invalid with decryption failed message");
        }
    }

    #[test]
    fn test_get_encrypted_record_invalid_data() {
        let mut store = PinsetStore::new();
        let mut record = create_test_record();

        // Create a record with invalid encrypted data (too short)
        record.key_data = zeroize::Zeroizing::from(vec![0u8; 5].into_boxed_slice());
        store.records.push(record.clone());

        let key = create_test_key();
        let result = store.get_encrypted_record(&record.peer_id, &key);
        assert!(result.is_err());

        if let Err(PinsetError::Invalid(msg)) = result {
            assert_eq!(msg, "Invalid encrypted data: too short");
        } else {
            panic!("Expected PinsetError::Invalid with too short message");
        }
    }

    #[test]
    fn test_multiple_encrypted_records() {
        let mut store = PinsetStore::new();
        let key = create_test_key();

        // Create multiple test records
        let mut record1 = create_test_record();
        record1.peer_id[0] = 1;

        let mut record2 = create_test_record();
        record2.peer_id[0] = 2;
        record2.key_data =
            zeroize::Zeroizing::from(b"different_key_data".to_vec().into_boxed_slice());

        // Add both records
        store.add_encrypted_record(&record1, &key).unwrap();
        store.add_encrypted_record(&record2, &key).unwrap();

        assert_eq!(store.records.len(), 2);

        // Retrieve and verify both records
        let decrypted1 = store
            .get_encrypted_record(&record1.peer_id, &key)
            .unwrap()
            .unwrap();
        let decrypted2 = store
            .get_encrypted_record(&record2.peer_id, &key)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted1.peer_id, record1.peer_id);
        assert_eq!(decrypted1.key_data.as_ref(), record1.key_data.as_ref());

        assert_eq!(decrypted2.peer_id, record2.peer_id);
        assert_eq!(decrypted2.key_data.as_ref(), record2.key_data.as_ref());

        // Verify they have different encrypted data
        assert_ne!(
            store.records[0].key_data.as_ref(),
            store.records[1].key_data.as_ref()
        );
    }

    #[test]
    fn test_encrypted_record_with_expiration() {
        let mut store = PinsetStore::new();
        let key = create_test_key();

        let expiration_time = Utc::now() + chrono::Duration::hours(1);
        let record = create_test_record().with_expiration(expiration_time);

        store.add_encrypted_record(&record, &key).unwrap();
        let decrypted = store
            .get_encrypted_record(&record.peer_id, &key)
            .unwrap()
            .unwrap();

        // Compare timestamps to account for serialization precision differences
        assert_eq!(
            decrypted.expires_at.unwrap().timestamp(),
            record.expires_at.unwrap().timestamp()
        );
    }

    #[test]
    fn test_nonce_uniqueness() {
        let mut store = PinsetStore::new();
        let record = create_test_record();
        let key = create_test_key();

        // Add the same record multiple times
        store.add_encrypted_record(&record, &key).unwrap();
        store.add_encrypted_record(&record, &key).unwrap();

        assert_eq!(store.records.len(), 2);

        // Extract nonces from both encrypted records
        let nonce1 = &store.records[0].key_data[..12];
        let nonce2 = &store.records[1].key_data[..12];

        // Nonces should be different (very high probability)
        assert_ne!(nonce1, nonce2);

        // Both should decrypt to the same original data
        let decrypted1 = store
            .get_encrypted_record(&record.peer_id, &key)
            .unwrap()
            .unwrap();
        let decrypted2 = store
            .get_encrypted_record(&record.peer_id, &key)
            .unwrap()
            .unwrap();

        assert_eq!(decrypted1.key_data.as_ref(), decrypted2.key_data.as_ref());
    }
}
