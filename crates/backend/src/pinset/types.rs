/*
possible on disk format reference

Header

MAGIC (4 bytes): PSET
version (u32 BE)
aead_alg (u8)
key_source (u8)
seq(u64 BE)
store_id_len (u16 BE), store_id (bytes)
nonce_len (u8), nonce (bytes)
kdf_length, kdf
kek_locator_length, kek_locator
end (single terminator)

Body (AEAD sealed blob)

record_count (u32 BE)

For each record

peer_id_len(u16) + peer_id
key_type (u8)
key_len (u16) + key_data
added_at (u64 BE)
has_expires (u8 0/1) + expires_at (u64 BE if present)
flags (u8)

*/

use std::io::{Read, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::pinset::codec::{TlvDecode, TlvEncode}; // We do not need serde for TLV. We need to hand roll our encoding and decoding, unless you want to keep it for debugging purposes
pub const MAGIC: [u8; 4] = *b"PSET";

pub type Result<T> = std::result::Result<T, PinsetError>;

#[derive(thiserror::Error, Debug)]
pub enum PinsetError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid header: {0}")]
    Invalid(&'static str),

    #[error("bad magic")]
    BadMagic,

    #[error("buffer is full (capacity: {0})")]
    BufferFull(usize),

    #[error("index out of bounds: {index}, length: {len}")]
    OutOfBounds { index: usize, len: usize },

    #[error("invalid UTF-8 sequence")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    //Change this as needed, we can easily add appropriate impl's on.
    Ed25519 = 1,
    Spki = 2,
    PqHybrid = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AeadAlgorithm {
    AesGcm = 1, //Add others as appropriate
}

impl AeadAlgorithm {
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadAlgorithm::AesGcm => 12, // 96-bit GCM nonces
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeySource {
    OsKeyStore = 1, //As above
    PassphraseKdf = 2,
}

// TODO: make flags a bitmask instead of an enum
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PinsetFlags {
    Active,
    Retired,
    Tofu, //I'm not googling this, too tired.
}

/*

reference for myself
magic number (i.e "pinsetstore" or "PSET")
version
aead_alg (Probably AES-GCM)
key_source (OSKeyStore, PassphraseKDF)
kdf (optional for passphrase mode)
kek_locator (optional for OS key store mode)
store_id (salt for KEK)
seq (increments each save and used for unique nonce making)
nonce (for AES-GCM)
wrap (optional wrap FEK under a KEK)

*/

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PinsetHeader {
    pub version: u32,
    pub aead_alg: AeadAlgorithm,
    pub key_source: KeySource,
    pub kdf: Option<String>,
    pub kek_locator: Option<String>, //This needs to be changed at some point, probably? I'm concerned about utf16 windows
    pub store_id: Vec<u8>,           // This can probablyy
    pub seq: u64,
    pub nonce: Vec<u8>,
    pub wrap: Option<Vec<u8>>,
}

impl PinsetHeader {
    pub const fn builder(
        version: u32,
        aead_alg: AeadAlgorithm,
        key_source: KeySource,
        store_id: Vec<u8>,
        nonce: Vec<u8>,
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

    pub const fn validate(&self) -> Result<()> {
        // Add some error handling here tomorrow
        if self.version == 0 {
            return Err(PinsetError::Invalid("Version must be >= 1"));
        }

        let expected = self.aead_alg.nonce_len();
        if self.nonce.len() != expected {
            return Err(PinsetError::Invalid("Invalid nonce length"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        // Ok(buffer)
        <Self as TlvEncode>::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as TlvDecode>::decode(bytes)
    }

    pub fn write_to(&self, w: impl Write) -> Result<()> {
        <Self as TlvEncode>::encode_to(self, w)
    }

    pub fn from_reader(r: impl Read) -> Result<Self> {
        <Self as TlvDecode>::decode_from(r)
    }
}

pub struct HeaderBuilder {
    version: u32, // Why should version be this big? //Alex- Redundancy, could it be a u8 or u16?
    aead_alg: AeadAlgorithm,
    key_source: KeySource,
    kdf: Option<String>,
    kek_locator: Option<String>,
    store_id: Vec<u8>,
    seq: u64,
    nonce: Vec<u8>,
    wrap: Option<Vec<u8>>,
}

impl HeaderBuilder {
    pub fn kdf<S: Into<String>>(mut self, s: S) -> Self {
        self.kdf = Some(s.into());
        self
    }

    pub fn kek_locator<S: Into<String>>(mut self, s: S) -> Self {
        self.kek_locator = Some(s.into());
        self
    }

    pub const fn seq(mut self, s: u64) -> Self {
        self.seq = s;
        self
    }

    pub fn wrap(mut self, w: Vec<u8>) -> Self {
        self.wrap = Some(w);
        self
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetRecord {
    pub peer_id: Vec<u8>, // Can this be a stack allocated?
    pub key_type: KeyType,
    pub key_data: Vec<u8>, // same as above ^
    pub added_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub flags: PinsetFlags, // TODO: change to bitmask (probably u8)
}

impl PinsetRecord {
    pub const fn new(
        peer_id: Vec<u8>,
        key_type: KeyType,
        key_data: Vec<u8>,
        added_at: DateTime<Utc>,
        flags: PinsetFlags,
    ) -> Self {
        Self {
            peer_id,
            key_type,
            key_data,
            added_at,
            expires_at: None,
            flags,
        }
    }

    pub const fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self, current_time: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| current_time > exp)
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.flags, PinsetFlags::Active)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        // Ok(buffer)
        <Self as TlvEncode>::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as TlvDecode>::decode(bytes)
    }

    pub fn write_to(&self, w: impl Write) -> Result<()> {
        <Self as TlvEncode>::encode_to(self, w)
    }

    pub fn from_reader(r: impl Read) -> Result<Self> {
        <Self as TlvDecode>::decode_from(r)
    }
}

#[cfg(test)]
mod tests;
