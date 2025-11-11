use crate::pinset::{
    crypto::{decrypt_body, encrypt_body},
    keychain::{
        KeyAttributes, KeychainError, SecureKey, default_keychain, kek_identifier_for_store,
    },
    types::{
        AeadAlgorithm, KeySource, PinsetError, PinsetHeader, PinsetRecord, decode_body, encode_body,
    },
};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(thiserror::Error, Debug)]
pub enum PinsetStoreError {
    #[error(transparent)]
    Pinset(#[from] PinsetError),

    #[error(transparent)]
    Keychain(#[from] KeychainError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetStore {
    path: PathBuf,
    header: PinsetHeader,
    records: Vec<PinsetRecord>,
    dirty: bool,
}

pub type StoreResult<T> = Result<T, PinsetStoreError>;

impl PinsetStore {
    pub fn create_os_keystore(path: impl AsRef<Path>) -> StoreResult<Self> {
        let path = path.as_ref().to_path_buf();

        // store_id (16 bytes)
        let mut store_id = [0u8; 16];
        OsRng.fill_bytes(&mut store_id);

        // FEK / KEK key material (placeholder: 32 random bytes)
        let mut fek = vec![0u8; 32]; // 256-bit FEK
        OsRng.fill_bytes(&mut fek);

        let keychain = default_keychain()?;
        let kek_id = kek_identifier_for_store(&store_id);
        let kek = SecureKey::from_vec(fek.clone());

        // Store key into OS keychain
        let attributes = KeyAttributes::new(kek_id.clone());
        keychain.store_key(kek, attributes)?;

        let seq = 0u64;
        // TODO move derive_nonce to types or something
        let nonce = Self::derive_nonce(&store_id, seq);

        let locator_str = kek_id.to_string();
        // let kek_locator = Some(OsStr::new(&locator_str).into());
        let locator_os: OsString = locator_str.into();

        let header = PinsetHeader::builder(
            1,
            AeadAlgorithm::AesGcm,
            KeySource::OsKeyStore,
            store_id,
            nonce,
        )
        .kek_locator(&locator_os)
        .seq(seq)
        .build()?;

        let mut store = Self {
            path,
            header,
            records: Vec::new(),
            dirty: true,
        };

        store.save_inner()?;
        store.dirty = false;

        Ok(store)
    }

    pub fn create_with_passphrase(
        _path: impl AsRef<Path>,
        _passphrase: Zeroizing<String>,
    ) -> StoreResult<Self> {
        todo!()
    }

    pub fn open(
        path: impl AsRef<Path>,
        _passphrase: Option<Zeroizing<String>>,
    ) -> StoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = File::open(&path)?;

        // Read header
        let header = PinsetHeader::read_tlv(&mut f)?;

        // Read body
        let mut ciphertext = Vec::new();
        f.read_to_end(&mut ciphertext)?;

        let records = match header.key_source {
            KeySource::OsKeyStore => Self::decrypt_with_os_keystore(&header, &ciphertext)?,
            KeySource::PassphraseKdf => {
                todo!()
            }
        };

        Ok(Self {
            path,
            header,
            records,
            dirty: false,
        })
    }

    pub fn find_by_peer_id(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn records(&self) -> &[PinsetRecord] {
        &self.records
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &PinsetRecord> {
        self.records.iter()
    }

    pub fn add_record(&mut self, record: PinsetRecord) {
        self.records.push(record);
        self.dirty = true;
    }

    pub fn remove_record(&mut self, peer_id: &[u8; 32]) -> Option<PinsetRecord> {
        if let Some(pos) = self.records.iter().position(|r| &r.peer_id == peer_id) {
            self.dirty = true;
            Some(self.records.remove(pos))
        } else {
            None
        }
    }

    pub fn get_record(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn cleanup_expired(&mut self, now: DateTime<Utc>) {
        self.records.retain(|r| !r.is_expired(now));
        // Random comment, retain isn't *actually* performant
        //https://github.com/rust-lang/rust/issues/91497
        // I'm going to just leave this here if anyone wants to look at it (i tested this last week but it's really concise and readable for now!)
        self.dirty = true;
    }

    pub fn upsert(&mut self, record: PinsetRecord) {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|r| r.peer_id == record.peer_id)
        {
            *existing = record;
        } else {
            self.records.push(record);
        }
        self.dirty = true;
    }

    // pub fn get_active_records(&self) -> Vec<&PinsetRecord> {
    //     self.records
    //         .iter()
    //         .filter(|r| matches!(r.flags, PinsetFlags::Active))
    //         .collect()
    // }

    pub fn save(&mut self) -> StoreResult<()> {
        if !self.dirty {
            return Ok(());
        }
        match self.header.key_source {
            KeySource::OsKeyStore => self.save_inner()?,
            KeySource::PassphraseKdf => {
                todo!()
            }
        }
        self.dirty = false;
        Ok(())
    }

    fn derive_nonce(store_id: &[u8; 16], seq: u64) -> [u8; 12] {
        let mut h = Hasher::new();
        h.update(store_id);
        h.update(&seq.to_be_bytes());
        let hash = h.finalize();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash.as_bytes()[..12]);
        nonce
    }

    fn save_inner(&mut self) -> StoreResult<()> {
        let keychain = default_keychain()?;
        let kek_id = kek_identifier_for_store(&self.header.store_id);
        let kek = keychain.retrieve_key(&kek_id)?;

        // Bump seq and nonce
        self.header.seq = self.header.seq.wrapping_add(1);
        self.header.nonce = Self::derive_nonce(&self.header.store_id, self.header.seq);

        let plaintext = encode_body(&self.records)?;
        let ciphertext =
            encrypt_body(&self.header, &kek, &plaintext).map_err(PinsetStoreError::from)?;

        let mut f = File::create(&self.path)?;
        self.header.write_tlv(&mut f)?;
        f.write_all(&ciphertext)?;

        Ok(())
    }

    fn decrypt_with_os_keystore(
        header: &PinsetHeader,
        ciphertext: &[u8],
    ) -> StoreResult<Vec<PinsetRecord>> {
        let keychain = default_keychain()?;
        let kek_id = kek_identifier_for_store(&header.store_id);
        let kek = keychain.retrieve_key(&kek_id)?;

        let plaintext = decrypt_body(header, &kek, ciphertext).map_err(PinsetStoreError::from)?;
        let records = decode_body(&plaintext)?;
        Ok(records)
    }
}
