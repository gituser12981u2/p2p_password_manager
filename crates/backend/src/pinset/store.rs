//! Persistent encrypted store for pinset records.
//!
//! # Overview
//!
//! The `pinset::store` module defines [`PinsetStore`], a high-level API for creating, opening,
//! mutating, and persisting encrypted collections of [`PinsetRecord`].
//!
//! A `PinsetStore` is an encrypted on-disk file format consisting of two components:
//!
//! 1. **Header (plaintext + TLV-encoded extensions)**
//!    Contains metadata required to decrypt the body:
//!    - version
//!    - AEAD algorithm
//!    - key source (`OS keychain` or `passphrase-derived KDF`)
//!    - sequence number (`seq`) used to derive unique nonces
//!    - store_identifier (`store_id`)
//!    - `kek_locator` (where the KEK is stored, if using the OS keystore)
//!    - optional KDF + wrap fields for passphrase-protected stores
//!
//! 2. **Body (AEAD-sealed binary blob)**
//!    Stores a sequence of [`PinsetRecord`] values serialized in a compact, deterministic binary format (`PinsetBody`).
//!
//! The header is always written in plaintext for key lookup, while the body is always encrypted using the KEK.
//!
//! # Key Management Model
//!
//! Two persistence modes are supported:
//!
//! * **OS Keychain Mode**
//!   A fresh 32-byte KEK is generated and inserted into the platform's OS keychain.
//!   The header stores a stable identifier (`kek_locator`) allowing the KEK to be recovered at open time.
//!
//! * **Passphrase Mode** (not yet implemented)
//!   A KEK will be derived from a user passphrase using a memory-hard KDF.
//!
//! The store never stores key material unencrypted on disk. The FEK/KEK is
//! *only* stored in the OS keychain or derived on demand.
//!
//! # Nonce Derivation
//!
//! Every save operation increments a monotonic sequence number (`seq`) and derives a
//! new 96-bit nonce from:
//!
//! ```text
//! nonce = BLAKE3(store_id || seq)[0..12]
//! ```
//!
//! This ensures unique nonces for AES-GCM under the same KEK, provided the sequences does not repeat.
//!
//! # In-Memory Model
//!
//! When a store is opened:
//!
//! * The header is parsed from disk.
//! * The KEK is retrieved (OS keychain or passphrase).
//! * The encrypted body is decrypted and deserialized into a `Vec<PinsetRecord>`.
//! * The store begins with `dirty == false`.
//!
//! When records are modified (`add_record` , `upsert`, `remove_record`, `cleanup_expired`),
//! `dirty` is set to `true`.
//!
//! Calling [`PinsetStore::save`] encrypted and persists the updated body, bumping `seq` and refreshing the AEAD nonce.
//!
//! # Guarantees and Invariants
//!
//! * The body is never written unencrypted.
//! * `seq` strictly monotonically increases on every successful save (wrapping allowed, but uniqueness of `(store_id, seq)` must hold across uses).
//! * Records are atomic at the logical level: either the previous body remains intact or a successful save replaces it entirely.
//! * The KEK must remain accessible from the OS keychain or re-derivable; otherwise the store becomes unreadable.

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
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Error type returned by operations on a [`PinsetStore`].
///
/// This is a thin wrapper over lower-level error types used by the
/// pinset format and the underlying keychain / filesystem.
#[derive(thiserror::Error, Debug)]
pub enum PinsetStoreError {
    /// Error originating from the pinset encoding/decoding layer.
    #[error(transparent)]
    Pinset(#[from] PinsetError),

    /// Error originating from the OS keychain abstraction.
    #[error(transparent)]
    Keychain(#[from] KeychainError),

    /// Error originating from the I/O when reading or writing the store.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Encrypted on-disk store of peer pin records.
///
/// A `PinsetStore` is responsible for:
///
/// * Owning the path of the on-disk file.
/// * Tracking the header used to AEAD-seal the body.
/// * Holding the in-memory collection of [`PinsetRecord`]s.
/// * Tracking whether the in-memory view has diverged from disk via the internal `dirty` flag.
///
/// The body of the store is always stored encrypted on disk. Decryption and encryption as handled
/// transparently by [`PinsetStore::open`] and [`PinsetStore::save`], respectively.
///
/// # Examples
///
/// Creating a store, adding a record, saving, and reopening:
///
/// ```
/// use chrono::Utc;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let path = std::env::temp_dir().join("pinset-store-example.pset");
///
/// // Create a new store backed by the OS keychain.
/// let mut store = backend::pinset::store::PinsetStore::create_os_keystore(&path)?;
///
/// // Add a record for some peer.
/// let record = backend::pinset::types::PinsetRecord::new(
///     [0u8; 32],
///     backend::pinset::types::KeyType::Ed25519,
///     vec![1, 2, 3, 4],
///     Utc::now(),
///     backend::pinset::types::PinsetFlags::ACTIVE,
/// );
/// store.add_record(record);
/// store.save()?;
///
/// // Later, reopen and read records.
/// let reopened = backend::pinset::store::PinsetStore::open(&path, None)?;
/// assert_eq!(reopened.records().len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PinsetStore {
    /// Filesystem location of the underlying store file.
    path: PathBuf,
    /// Header metadata used to interpret and decrypt the body.
    header: PinsetHeader,
    /// In-memory collection of pin records contained from the on-disk file.
    records: Vec<PinsetRecord>,
    /// Tracks whether the in-memory state has diverged from the on-disk file.
    ///
    /// Mutating APIs set this flag to `true`; [`PinsetStore::save`] clears
    /// it after successfully persisting the new state.
    dirty: bool,
}

/// Convenience result type used by the `PinsetStore` API.
pub type StoreResult<T> = Result<T, PinsetStoreError>;

impl PinsetStore {
    /// Creates a new, empty pinset store backed by the OS keychain.
    ///
    /// This function:
    ///
    /// * Generates a fresh random `store_id` and FEK key material.
    /// * Stores the FEK in the platform OS keychain under a deterministic key identifier derived from `store_id`.
    /// * Constructs a [`PinsetHeader`] configured to use [`KeySource::OsKeyStore`] and [`AeadAlgorithm::AesGcm`].
    /// * Writes the header and an empty encrypted body to the given `path`.
    ///
    /// The store is returned with an empty set of records and `dirty == false`.
    ///
    /// # Arguments
    ///
    /// * `path` - Location of the store file to create. If a file already exists at this path, it will be truncated.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * The OS keychain cannot be accessed or fails to store the key.
    /// * The header fails validation / encoding.
    /// * The file cannot be created or written.
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

    /// Creates a pinset store protected by a passphrase-derived key.
    ///
    /// This is the counterpart to [`PinsetStore::create_os_keystore`] for environments where
    /// an OS keychain is not available or not desired.
    ///
    /// Implementations are expected to:
    ///
    /// * Derive a KEK from the provided passphrase (e.g., via Argon2id).
    /// * Configure the header with [`KeySource::PassphraseKdf`].
    /// * Seal and persist an empty record set at `path`.
    ///
    /// # Notes
    ///
    /// This function is currently not implemented and will panic at runtime.
    ///
    /// # Arguments
    ///
    /// * `path` - Location of the store file to create.
    /// * `passphrase` - Passphrase used to derive a KEK. Wrapped in [`Zeroizing`] to reduce the
    ///   chance of accidental leakage.
    pub fn create_with_passphrase(
        _path: impl AsRef<Path>,
        _passphrase: Zeroizing<String>,
    ) -> StoreResult<Self> {
        todo!()
    }

    /// Opens an existing pinset store from disk and decrypts its contents.
    ///
    /// The header is read and parsed first. The body is then decrypted using the key identified by the header:
    ///
    /// * For [`KeySource::OsKeyStore`], the KEK is retrieved from the OS keychain.
    /// * For [`KeySource::PassphraseKdf`], a passphrase-based derivation will be used (currently unimplemented).
    ///
    /// The returned store has `dirty == false`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to an existing pinset store file.
    /// * `_passphrase` - Optional passphrase for stores configured with [`KeySource::PassphraseKdf`]. Currently unused while that mode is unimplemented.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * The file cannot be opened or read.
    /// * The header TLV cannot be decoded or fails validation.
    /// * The key cannot be obtained from the keychain.
    /// * Decryption or decoding of the body fails.
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

    /// Looks up a record by its peer identifier.
    ///
    /// This is a read-only convenience wrapper which returns a shared reference.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Byte slice containing the peer identifier. For records created via [`PinsetRecord::new`], this is typically 32 bytes.
    ///
    /// # Returns
    ///
    /// `Some(&PinsetRecord)` if a record with the given peer id exists, otherwise `None`.
    pub fn find_by_peer_id(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    /// Returns an immutable slice of all records in the store.
    ///
    /// The slice is backed by the internal vector and is valid for the lifetime of `&self`.
    pub fn records(&self) -> &[PinsetRecord] {
        &self.records
    }

    /// Returns an iterator over all records in the store.
    ///
    /// This is equivalent to [`PinsetStore::records`] followed by `.iter()`, but the
    /// return type is an [`ExactSizeIterator`] for convenience.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &PinsetRecord> {
        self.records.iter()
    }

    /// Appends a new record to the store.
    ///
    /// This does not perform any deduplication; if one wants to replace an existing records
    /// for a peer, use [`PinsetStore::upsert`] instead.
    ///
    /// The store is marked `dirty`
    pub fn add_record(&mut self, record: PinsetRecord) {
        self.records.push(record);
        self.dirty = true;
    }

    /// Removes the first record whose `peer_id` matches the given identifier.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - 32-byte peer identifier to remove.
    ///
    /// # Returns
    ///
    /// * `Some(PinsetRecord)` if a record was found and removed.
    /// * `None` if no record matched the given `peer_id`.
    ///
    /// The store is marked `dirty` if a record is removed.
    pub fn remove_record(&mut self, peer_id: &[u8; 32]) -> Option<PinsetRecord> {
        if let Some(pos) = self.records.iter().position(|r| &r.peer_id == peer_id) {
            self.dirty = true;
            Some(self.records.remove(pos))
        } else {
            None
        }
    }

    /// Retrieves a record by its peer identifier.
    ///
    /// This is functionally identical to [`PinsetStore::find_by_peer_id`]
    /// and is provided for API ergonomics.
    pub fn get_record(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    /// Removes all records that have expired by the provided timestamp.
    ///
    /// Any record for which [`PinsetRecord::is_expired`] returns `true` with respect to `now` will be dropped.
    /// The store is marked `dirty` even if no record was actually removed.
    ///
    /// # Arguments
    ///
    /// * `now` - Timestamp used as the reference point for expiry checks.
    pub fn cleanup_expired(&mut self, now: DateTime<Utc>) {
        self.records.retain(|r| !r.is_expired(now));
        // Random comment, retain isn't *actually* performant
        //https://github.com/rust-lang/rust/issues/91497
        // I'm going to just leave this here if anyone wants to look at it (i tested this last week but it's really concise and readable for now!)
        self.dirty = true;
    }

    /// Inserts or updates a record for a given peer.
    ///
    /// If a record already exist whose `peer_id` matches that of `record`,
    /// it is replaced in-place. Otherwise, `record` is appended to the end of the collection.
    ///
    /// The store is marked `dirty` and will be persisted on the next call to [`PinsetStore::save`].
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

    /// Persists the store to disk if it has been modified.
    ///
    /// If `dirty` is `false`, this is a no-op and returns `Ok(())`.
    /// Otherwise, the current header / body are re-encrypted and written
    /// to `self.path`, and `dirt` is reset to `false` on success.
    ///
    /// The exact persistence backend depends on the [`KeySource`] specified in the header:
    ///
    /// * [`KeySource::OsKeyStore`] - the KEK is retrieved from the OS keychain.
    /// * [`KeySource::PassphraseKdf`] - passphrase-based mode (unimplemented).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * The KEK cannot be retrieved from the key source.
    /// * Encrypted or encoding fails.
    /// * The file cannot be created or written.
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

    /// Derives a deterministic AEAD nonce from the `store_id` and sequence number.
    ///
    /// This helper is used to generate nonces for successive saves. It uses
    /// BLAKE3 over the `store_id` and `seq` and truncates the result to the
    /// nonce length expected by the chosen AEAD algorithm (currently 12 bytes for AES-GCM).
    ///
    /// The combination `(store_id, seq)` must not repeat across encryptions for the same key.
    fn derive_nonce(store_id: &[u8; 16], seq: u64) -> [u8; 12] {
        let mut h = Hasher::new();
        h.update(&seq.to_be_bytes());
        h.update(store_id);
        let hash = h.finalize();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash.as_bytes()[..12]);
        nonce
    }

    /// Internal helper that performs the actual save for OS-keystore-backed stores.
    ///
    /// This:
    ///
    /// * Retrieves the KEK from the OS keychain.
    /// * Bumps the header sequence number and derives a fresh nonce.
    /// * Encodes the body, encrypts it, and writes header + ciphertext to `self.path`.
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

    /// Decrypts and decodes the store body using a key fetched from the OS keychain.
    ///
    /// This helper is used by [`PinsetStore::open`] for stores whose header is configured with [`KeySource::OsKeyStore`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * The KEK cannot be retrieved from the keychain.
    /// * AEAD decryption fails.
    /// * Decoding the plaintext body into [`PinsetRecord`]s fails.
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

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        time::UNIX_EPOCH,
    };

    use crate::pinset::{
        keychain::{KeychainError, default_keychain, kek_identifier_for_store},
        store::{PinsetStore, PinsetStoreError},
        types::{KeyType, PinsetFlags, PinsetHeader, PinsetRecord},
    };
    use chrono::Utc;
    use rand::RngCore;

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
    fn pinset_store_os_keystore_header_kek_locator_matches_internal_identifier_and_key_exists() {
        let temp_path = temp_store_path();
        PinsetStore::create_os_keystore(&temp_path).expect("Failed to create OS keystore");
        let header = read_header_from(&temp_path);

        let locator = header
            .kek_locator
            .as_ref()
            .expect("kek_locator should be present for OS keystore stores");
        let locator_str = locator
            .to_str()
            .expect("kek_locator should be valid UTF-8")
            .to_owned();

        // Derived KEK identifier from store_id should match the locator-derived identifier
        let kek_id = kek_identifier_for_store(&header.store_id);
        assert_eq!(
            locator_str,
            kek_id.to_unique_string(),
            "kek_locator must equal kek_identifier_for_store(store_id)"
        );

        // Check that identifier exists in the OS keystore
        let keychain = default_keychain().expect("Failed to create keychain");
        let exists = keychain
            .key_exists(&kek_id)
            .expect("key_exists check should succeed");
        assert!(
            exists,
            "KEK reference by kek_locator should exist in OS keychain after storing"
        );

        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn pinset_store_os_keystore_open_fails_after_kek_deleted() {
        let temp_path = temp_store_path();

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
        let mut f = std::fs::File::open(&temp_path).expect("Failed to open store file");
        let header =
            PinsetHeader::read_tlv(&mut f).expect("Failed to decode header for negative test");

        let keychain = default_keychain().expect("Failed to create keychain");
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
}
