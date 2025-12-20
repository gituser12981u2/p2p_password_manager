//! PinsetStore (PSET) core types and invariants.
//! 
//! This module defines the in-memory representations of:
//! 
//! - The unencrypted PSET header ([`PinsetHeader`])
//! - The individual pin records ([`PinsetRecord`])
//! - Enums and flags that map directly to on-disk discriminants.
//! 
//! The binary encoding/decoding rules live in `codec.rs` (TLV for header options,
//! and a fixed-field record encoding inside the AEAD body).
//! 
//! # On-disk format reference (PSET v1)
//! 
//! This is a compact reference for teh current on-disk layout. It is intended to 
//! be consistent with `codec.rs` and the project RFC [`pset-v1`]. 
//! 
//! ## High-level layout
//! 
//! ```text
//! +-------------------------+
//! | Header (unencrypted)    |
//! +-------------------------+
//! | Body (AEAD-sealed blob) |
//! +-------------------------+
//! ```
//! 
//! ## Header layout (fixed prefix + TLVs)
//!
//! ```text
//! MAGIC     (4 bytes): "PSET"
//! version    (u8)
//! aead_alg   (u8)
//! key_source (u8)
//! seq        (u64, big-endian)
//! store_id   (16 bytes)
//! nonce      (12 bytes for AES-GCM)
//! [ TLVs ]
//!   TLV: type(u8), len(u16 BE), value([len])
//!   types: 0x01=KDF, 0x02=KEK_LOCATOR, 0x03=WRAP, 0x7F=END
//! ```
//! 
//! - The TLV section terminates with a single `0x7F` byte (`TLV_END`), with no length/value.
//! - Unknown `version` / `aead_alg` / `key_source` values should be rejected. 
//! 
//! ## Body layout (AEAD sealed blob)
//! 
//! ```text
//! record_count (u32, big-endian)
//! 
//! For each record:
//!  peer_id_len (u32, big-endian)
//!  peer_id     ([peer_id_len] bytes)
//!  key_type    (u8)
//!  key_len     (u16)
//!  key_data    ([key_len] bytes)
//!  added_at    (u64, big-endian) // Unix timestamp
//!  has_expires (u8: 0 or 1)
//!  expires_at  (u64, big-endian) // iff has_expires == 1
//!  flags       (u8)              // bitmask
//! ```
//! 
//! # Security notes
//! 
//! - The header is unencrypted and must not contain secret key material.
//! - Secret bytes that exist in-memory (e.g., wrapped keys, pinned public keys) are held
//! in [`zeroize::Zeroizing`] containers where feasible.
//! - For AES-GCM, nonce reuse with the same key is catastrophic; nonce construction
//! must guarantee uniqueness per key (see store logic for `seq`-based derivation).

use crate::pinset::codec::{PinsetBody, TlvDecode, TlvEncode};
use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::{Read, Write};
use zeroize::Zeroizing; // We do not need serde for TLV. We need to hand roll our encoding and decoding, unless you want to keep it for debugging purposes

/// The 4-byte magic prefix for all PSET files (`b"PSET"`).
/// 
/// Readers must reject files whose first 4 bytes do not match this value.
pub const MAGIC: [u8; 4] = *b"PSET";

/// Result alias for PinsetStore operations.
pub type Result<T> = std::result::Result<T, PinsetError>;

/// Errors for PinsetStore parsing, validation, and IO.
/// 
/// This error surface is compact. Lower-level errors are wrapped (e.g. `std::io::Error`)
/// while format violations map to [`PinsetError::Invalid`] or more specific variants (e.g. [`PinsetError::BadMagic`]).
#[derive(thiserror::Error, Debug)]
pub enum PinsetError {
    /// A required field was absent when constructing or decoding a value. 
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A structural or semantic format violation
    #[error("invalid header: {0}")]
    Invalid(&'static str),

    /// File magic did not match [`MAGIC`].
    #[error("bad magic")]
    BadMagic,

    /// An internal fixed-capacity buffer was insufficient.
    #[error("buffer is full (capacity: {0})")]
    BufferFull(usize),

    /// Bounds violation when indexing into a buffer.
    #[error("index out of bounds: {index}, length: {len}")]
    OutOfBounds { index: usize, len: usize },

    /// UTF-8 parsing failed for fields that must be valid UTF-8 (e.g. KDF name).
    #[error("invalid UTF-8 sequence")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// Underlying IO errors.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Identifies the type/format of the pinned key material in a record.
/// 
/// This is written to disk as a `u8` discriminant (see `codec.rs` mapping).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 public key bytes.
    Ed25519 = 1,
    /// SPKI-encoded public key bytes.
    Spki = 2,
    /// Post-quantum hybrid public key representation.
    PqHybrid = 3,
}

/// Supported AEAD algorithms for sealing the body.
/// 
/// This is written to disk as a `u8` discriminant(see `codec.rs` mapping).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-256-GC with a 96-bit (12-byte) nonce.
    AesGcm = 1, 
}

impl AeadAlgorithm {
    /// Returns the required nonce length (in bytes) for this AEAD algorithm.
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadAlgorithm::AesGcm => 12, // 96-bit GCM nonces
        }
    }
}

/// Declares how the Key Encryption Key (KEK) is obtained.
/// 
/// This is written to disk as a `u8` discriminant (see `codec.rs` mapping).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeySource {
    /// KEK is stored in an OS credential manager / keystore.
    OsKeyStore = 1, 
    /// KEK is derived form a user passphrase using a KDF described in the header TLVs.
    PassphraseKdf = 2,
}

bitflags! {
    /// Per-record flags (bitmask).
    /// 
    /// These flags are stored as a single `u8` in each record.
    /// 
    /// Invariants:
    /// - `ACTIVE` and `RETIRED` must not be se simultaneously.
    /// - Upper bits are reserved for future versions and should be rejected 
    ///   according to policy (current codec rejected invalid bit patterns via `from_bits`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PinsetFlags: u8 {
        /// Record is currently valid for pin checks.
        const ACTIVE = 0b0000_0001;
        /// Record is retained for history but should not be used for current checks.
        const RETIRED = 0b0000_0010;
        /// Trust-on-first-use marker (policy-dependent).
        const TOFU = 0b0000_0100;
        // Note: 0b1111_1000 bits are reserved for future use.
    }
}

impl PinsetFlags {
    /// Reserved bits that should not be set in current version.
    pub const RESERVED: u8 = 0b1111_1000;

    /// Returns a copy with `ACTIVE` set and `RETIRED` cleared. 
    pub fn set_active(mut self) -> Self {
        self.remove(PinsetFlags::RETIRED);
        self.insert(PinsetFlags::ACTIVE);
        self
    }

    /// Returns a copy with `RETIRED` set and `ACTIVE` cleared.
    pub fn set_retired(mut self) -> Self {
        self.remove(PinsetFlags::ACTIVE);
        self.insert(PinsetFlags::RETIRED);
        self
    }

    /// Returns `true` if the flags are semantically valid for current version. 
    /// 
    /// Currently enforces: not both `ACTIVE` and `RETIRED`.
    pub fn is_valid(&self) -> bool {
        !(self.contains(PinsetFlags::ACTIVE) && self.contains(PinsetFlags::RETIRED))
    }
}


/// Unencrypted PSET header (fixed prefix + optional TLVs).
/// 
/// The header is designed to be:
/// - Small and strictly parsed.
/// - Extensible via TLVs.
/// - Safe to store in plaintext (no secret key material). 
/// 
/// ## Optional TLVs
/// 
/// These fields are encoded as TLVs in `codec.rs`:
/// - `kdf`: describes KDF parameters or identifier for `KeySource::PassphraseKdf`.
/// - `kek_locator`: optional OS-keystore locator hint (platform-specific bytes).
/// - `wrap`: optional wrapped key material (implementation-defined).
/// 
/// Callers must enforce a coherent header:
/// - For `KeySource::PassphraseKdf`, a `kdf` TLV must be present.
/// - For `KeySource::OsKeyStore`, a `kek_locator` TLV may be present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinsetHeader {
    /// File format version (PSET v1 = 1).
    pub version: u8,

    /// AEAD algorithm used to seal the body.
    pub aead_alg: AeadAlgorithm,

    /// Declares how the KEK is obtained.
    pub key_source: KeySource,

    /// Optional KDF descriptor (meaning depends on KDF scheme/version).
    pub kdf: Option<Box<str>>,

    /// Optional OS-keystore locator (platform-encoded bytes).
    /// 
    /// This may contain a serialized form of [`crate::pinset::keychain::KeyIdentifier`]
    /// or another backend-specific reference. It is stored in plaintext in the header.
    pub kek_locator: Option<Box<OsStr>>,

    /// Store identifier (opaque 16 bytes).
    pub store_id: [u8; 16],

    /// Monotonic sequence number (big-endian on disk).
    /// 
    /// Intended for nonce derivation and/or anti-rollback checks at the store layer.
    pub seq: u64,

    /// AEAD nonce (AES-GCM requires 12 bytes).
    pub nonce: [u8; 12],

    /// Optional wrapped key material.
    /// 
    /// This is treated as sensitive bytes in-memory and will be zeroized on drop.
    pub wrap: Option<Zeroizing<Box<[u8]>>>,
}

impl PinsetHeader {
    /// Starts a builder for a header with required fields.
    /// 
    /// The builder initializes:
    /// - `seq` to `0`.
    /// - optional fields (`kdf`, `kek_locator`, `wrap`) to `None`.
    /// 
    /// Call [`HeaderBuilder::build`] to validate invariants (nonce length, version).
    pub const fn builder(
        version: u8,
        aead_alg: AeadAlgorithm,
        key_source: KeySource,
        store_id: [u8; 16],
        nonce: [u8; 12],
    ) -> HeaderBuilder {
        HeaderBuilder {
            version,
            aead_alg,
            key_source,
            kdf: None,
            kek_locator: None,
            store_id,
            seq: 0,
            nonce,
            wrap: None,
        }
    }

    /// Validates semantic invariants for the current header version.
    /// 
    /// This does not validate policy-level coherence (e.g. "kdf  must exist when `key_source == PassphraseKdf`).")
    /// 
    /// Current checks:
    /// - `version` must be >= 1
    /// - `nonce` length must match `aead_alg.nonce_len()`
    pub fn validate(&self) -> Result<()> {
        // TODO: Add some error handling here tomorrow
        // --Alex gotta add some more validation soon
        match self.version {
            0 => return Err(PinsetError::Invalid("Version must be >= 1")),
            v if v > u8::MAX - 1 => {
                return Err(PinsetError::Invalid(
                    "Version must be <= 256 to avoid potential overflow",
                ));
            }
            _ => {} // Valid version, continue validation
        }
        if self.nonce.len() != self.aead_alg.nonce_len() {
            return Err(PinsetError::Invalid("Invalid nonce length"));
        }
        Ok(())
    }

    /// Encodes the header in binary format (fixed prefix + TLVs + TLV_END).
    pub fn encode_tlv(&self) -> Result<Vec<u8>> {
        <Self as TlvEncode>::encode(self)
    }

    /// Decodes a header from binary format.
    pub fn decode_tlv(bytes: &[u8]) -> Result<Self> {
        <Self as TlvDecode>::decode(bytes)
    }

    /// Writes the encoded header to a writer.
    pub fn write_tlv(&self, w: impl Write) -> Result<()> {
        <Self as TlvEncode>::encode_to(self, w)
    }

    /// Reads and decodes a header from a reader.
    pub fn read_tlv(r: impl Read) -> Result<Self> {
        <Self as TlvDecode>::decode_from(r)
    }
}

/// Builder for [`PinsetHeader`].
/// 
/// This exists to make required fields explicit and to keep validation centralized
/// in [`HeaderBuilder::build`].
pub struct HeaderBuilder {
    version: u8,
    aead_alg: AeadAlgorithm,
    key_source: KeySource,
    kdf: Option<Box<str>>,
    kek_locator: Option<Box<OsStr>>,
    store_id: [u8; 16],
    seq: u64,
    nonce: [u8; 12],
    wrap: Option<Zeroizing<Box<[u8]>>>,
}

impl HeaderBuilder {
    /// Sets the optional KDF descriptor.
    pub fn kdf<S: Into<Box<str>>>(mut self, s: S) -> Self {
        self.kdf = Some(s.into());
        self
    }

    /// Sets the optional OS-keystore locator.
    pub fn kek_locator<S: AsRef<OsStr> + ?Sized>(mut self, s: &S) -> Self {
        self.kek_locator = Some(s.as_ref().into());
        self
    }

    /// Sets the sequence number.
    pub const fn seq(mut self, s: u64) -> Self {
        self.seq = s;
        self
    }

    /// Sets optional wrapped key bytes (treated as sensitive and zeroized on drop).
    pub fn wrap(mut self, w: impl Into<Box<[u8]>>) -> Self {
        let boxed: Box<[u8]> = w.into();
        self.wrap = Some(Zeroizing::from(boxed));
        self
    }

    /// Builds and validates the header.
    pub fn build(self) -> Result<PinsetHeader> {
        let header = PinsetHeader {
            version: self.version,
            aead_alg: self.aead_alg,
            key_source: self.key_source,
            kdf: self.kdf,
            kek_locator: self.kek_locator,
            store_id: self.store_id,
            seq: self.seq,
            nonce: self.nonce,
            wrap: self.wrap,
        };
        header.validate()?;
        Ok(header)
    }
}

/// Encodes records into the AEAD plaintext body format.
/// 
/// This produces the bytes that are then sealed by the AEAD layer.
/// The encoding is `record_count (u32 BE)` followed by each record's fixed-field encoding
/// (see [`PinsetRecord`] and `codec.rs`). 
pub(crate) fn encode_body(records: &[PinsetRecord]) -> Result<Vec<u8>> {
    let body = PinsetBody {
        records: records.to_vec(),
    };
    body.encode()
}

/// Decodes records from the AEAD plaintext body format.
/// 
/// Callers are expected to AEAD-decrypt the body first; this functions operates on
/// the decrypted plaintext. 
pub(crate) fn decode_body(bytes: &[u8]) -> Result<Vec<PinsetRecord>> {
    let body = PinsetBody::decode(bytes)?;
    Ok(body.records)
}

/// A single pinned peer record stored inside the AEAD-protected body.
/// 
/// This is the atomic unit used for "connect quickly" pin checks.
/// 
/// ## Field semantics
/// 
/// - `peer_id` is fixed as 32 bytes in-memory and currently encoded on disk with
///    a `peer_id_len` prefix that must equal 32.
/// - `key_data` holds the pinned key material (public key or other representation),
///    stored as bytes. It is kept in the zeroizing container because it is security-relevant.
/// - `added_at` / `expires-at` are UTC timestamps (seconds precision in the current codec).
/// - `flags` carries record state such as active/retired/tofu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetRecord {
    /// 32-byte peer identifier.
    pub peer_id: [u8; 32],
    
    /// Declares how to interpret `key_data`.
    pub key_type: KeyType,

    /// Pinned key bytes (security-relevant; zeroized on drop).
    pub key_data: Zeroizing<Box<[u8]>>, 
    
    /// When the record was added (UTC). 
    pub added_at: DateTime<Utc>,

    /// Optional expiration time (UTC).
    pub expires_at: Option<DateTime<Utc>>,

    /// Per-record flags.
    pub flags: PinsetFlags,
}

impl PinsetRecord {
    /// Creates a new record without expiration.
    /// 
    /// Call [`PinsetRecord::with_expiration`] to attach an expiration timestamp.
    pub fn new(
        peer_id: [u8; 32],
        key_type: KeyType,
        key_data: impl Into<Box<[u8]>>,
        added_at: DateTime<Utc>,
        flags: PinsetFlags,
    ) -> Self {
        let boxed: Box<[u8]> = key_data.into();
        Self {
            peer_id,
            key_type,
            key_data: Zeroizing::from(boxed),
            added_at,
            expires_at: None,
            flags,
        }
    }

    /// Returns a copy of this record with an expiration time set.
    pub const fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Returns `true` if the record is expired at `current_time`.
    pub fn is_expired(&self, current_time: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| current_time > exp)
    }

    /// Returns `true` if the record is marked active.
    pub const fn is_active(&self) -> bool {
        self.flags.contains(PinsetFlags::ACTIVE)
    }

    /// Encodes this record into the body record format.
    pub fn encode_tlv(&self) -> Result<Vec<u8>> {
        <Self as TlvEncode>::encode(self)
    }

    /// Decodes a record from bytes.
    pub fn decode_tlv(bytes: &[u8]) -> Result<Self> {
        <Self as TlvDecode>::decode(bytes)
    }

    /// Writes the record encoding to a writer.
    pub fn write_tlv(&self, w: impl Write) -> Result<()> {
        <Self as TlvEncode>::encode_to(self, w)
    }

    /// Reads the decodes a record from a reader.
    pub fn read_tlv(r: impl Read) -> Result<Self> {
        <Self as TlvDecode>::decode_from(r)
    }
}

#[cfg(test)]
mod tests;
