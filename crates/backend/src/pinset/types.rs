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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize}; // We do not need serde for TLV. We need to hand roll our encoding and decoding, unless you want to keep it for debugging purposes
use std::borrow::Cow;
use std::io::{Read, Write};
pub const MAGIC: [u8; 4] = *b"PSET";

pub type Result<T> = std::result::Result<T, PinsetError>;

use core::ops::{Index, IndexMut};

impl<const N: usize> Index<usize> for GenericArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if index >= self.len {
            panic!(
                "index out of bounds: the len is {} but the index is {index}",
                self.len
            );
        }
        &self.buf[index]
    }
}

impl<const N: usize> IndexMut<usize> for GenericArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index >= self.len {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.len, index
            );
        }
        &mut self.buf[index]
    }
}

#[derive(Debug, Clone, Copy)]
/// A simple stack-allocated array with convenience methods for string/byte operations.
pub struct GenericArray<const N: usize> {
    /// The underlying byte buffer with fixed capacity N
    buf: [u8; N],
    /// Current length of valid data (excluding null terminator)
    len: usize,
}

impl<const N: usize> GenericArray<N> {
    pub const fn new() -> Self {
        // Do we use maybeuninit here until initialised?
        // Do we also used unchecked methods? seems pointless to use plain indexing if the bounds are already checked
        // I've avoided this because I don't want to necessarily add unsafe code with no perf gain (some people have fiery opinions about it!)
        let mut buf = [0u8; N];
        buf[0] = 0;
        Self { buf, len: 0 }
    }

    /// Creates a GenericArray from a byte slice or string slice.
    ///
    /// `input` - A type that can be converted to a byte slice (&str, &[u8], String, etc.)
    pub fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Result<Self> {
        let bytes = input.as_ref();

        if bytes.len() + 1 > N {
            return Err(PinsetError::BufferFull(N));
        }

        let mut buf = [0u8; N];
        let mut len = 0;

        while len < bytes.len() {
            buf[len] = bytes[len];
            len += 1;
        }

        buf[len] = 0; // null terminator

        Ok(Self { buf, len })
    }

    pub const fn push(&mut self, byte: u8) -> Result<()> {
        if self.len + 1 >= N {
            return Err(PinsetError::BufferFull(N));
        }
        self.buf[self.len] = byte;
        self.len += 1;
        self.buf[self.len] = 0;
        Ok(())
    }

    pub const fn get(&self, index: usize) -> Result<u8> {
        if index >= self.len {
            return Err(PinsetError::OutOfBounds {
                index,
                len: self.len,
            });
        }
        Ok(self.buf[index])
    }

    pub fn as_str(&self) -> Result<&str> {
        let bytes = &self.buf[..self.len];
        Ok(core::str::from_utf8(bytes).map_err(PinsetError::Utf8Error)?)
    }

    pub fn to_str_lossy(&self) -> Cow<'_, str> {
        let bytes = &self.buf[..self.len];
        String::from_utf8_lossy(bytes)
    }

    pub const fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        N
    }
}

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
    pub fn from_reader<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(PinsetError::BadMagic);
        }

        let mut buf = [0u8; 4];
        r.read_exact(&mut buf)?;
        let version = u32::from_be_bytes(buf);

        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        let aead_alg = match buf[0] {
            1 => AeadAlgorithm::AesGcm,
            _ => return Err(PinsetError::Invalid("unknown AEAD algorithm")),
        };

        r.read_exact(&mut buf)?;
        let key_source = match buf[0] {
            1 => KeySource::OsKeyStore,
            2 => KeySource::PassphraseKdf,
            _ => return Err(PinsetError::Invalid("Unknown key source")),
        };

        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        let seq = u64::from_be_bytes(buf);

        let mut buf = [0u8; 2];
        r.read_exact(&mut buf)?;
        let store_id_len = u16::from_be_bytes(buf) as usize;
        let mut store_id = vec![0; store_id_len];
        r.read_exact(&mut store_id)?;

        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        let nonce_len = buf[0] as usize;
        let mut nonce = vec![0; nonce_len];
        r.read_exact(&mut nonce)?;

        // TODO: handle optional TLVs
        let kdf: Option<String> = None;
        let kek_locator: Option<String> = None;
        let wrap: Option<Vec<u8>> = None;

        let header = Self {
            version,
            aead_alg,
            key_source,
            kdf,
            kek_locator,
            store_id,
            seq,
            nonce,
            wrap,
        };

        header.validate()?;
        Ok(header)
    }

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
        // I switched the hardcoded 12 value to check for any aead alg as long as we impl it
        let expected = self.aead_alg.nonce_len();
        if self.nonce.len() != expected {
            return Err(PinsetError::Invalid("Invalid nonce length"));
        }
        Ok(())
    }

    pub fn write_to(&self, mut w: impl Write) -> Result<()> {
        self.validate()?;

        w.write_all(&MAGIC)?;
        w.write_all(&self.version.to_be_bytes())?;
        w.write_all(&[self.aead_alg as u8])?;
        w.write_all(&[self.key_source as u8])?;
        w.write_all(&self.seq.to_be_bytes())?;
        w.write_all(&(self.store_id.len() as u16).to_be_bytes())?;
        w.write_all(&self.store_id)?;
        w.write_all(&[self.nonce.len() as u8])?;
        w.write_all(&self.nonce)?;

        // TODO: Write the optional fields

        const TLV_END: u8 = 0x7F;
        w.write_all(&[TLV_END])?;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.write_to(&mut buffer)?;
        Ok(buffer)
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

    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        // Write peer_id_len (u16) + peer_id
        w.write_all(&(self.peer_id.len() as u16).to_be_bytes())?;
        w.write_all(&self.peer_id)?; //We could be more specific with error handling on write

        // Write key_type (u8)
        w.write_all(&[self.key_type as u8])?;

        // Write key_len (u16) + key_data
        w.write_all(&(self.key_data.len() as u16).to_be_bytes())?;
        w.write_all(&self.key_data)?;

        // Write added_at (u64 BE) as Unix timestamp
        w.write_all(&self.added_at.timestamp().to_be_bytes())?;

        // Write has_expires (u8 0/1) + expires_at (u64 BE if present)
        match self.expires_at {
            Some(expires) => {
                w.write_all(&[1u8])?; // has_expires = 1
                w.write_all(&expires.timestamp().to_be_bytes())?;
            }
            None => {
                w.write_all(&[0u8])?; // has_expires = 0
            }
        }

        // Write flags (u8)
        let flags_byte = match self.flags {
            PinsetFlags::Active => 0,
            PinsetFlags::Retired => 1,
            PinsetFlags::Tofu => 2,
        };
        w.write_all(&[flags_byte])?;

        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.write_to(&mut buffer)?;
        Ok(buffer)
    }

    pub fn from_reader<R: Read>(mut r: R) -> Result<Self> {
        let mut buf = [0u8; 8]; // big enough for the largest read

        // Read peer_id_len (u16) + peer_id
        r.read_exact(&mut buf[..2])?;
        let peer_id_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let mut peer_id = vec![0; peer_id_len];
        r.read_exact(&mut peer_id)?;

        // Read key_type (u8)
        r.read_exact(&mut buf[..1])?;
        let key_type = match buf[0] {
            1 => KeyType::Ed25519,
            2 => KeyType::Spki,
            3 => KeyType::PqHybrid,
            _ => return Err(PinsetError::Invalid("unknown key type")),
        };

        // Read key_len (u16) + key_data
        r.read_exact(&mut buf[..2])?;
        let key_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let mut key_data = vec![0; key_len];
        r.read_exact(&mut key_data)?;

        // Read added_at (u64 BE) as Unix timestamp
        r.read_exact(&mut buf[..8])?;
        let added_at_timestamp = i64::from_be_bytes(buf);
        let added_at = DateTime::from_timestamp(added_at_timestamp, 0)
            .ok_or(PinsetError::Invalid("invalid added_at timestamp"))?;

        // Read has_expires (u8 0/1) + expires_at (u64 BE if present)
        r.read_exact(&mut buf[..1])?;
        let expires_at = if buf[0] == 1 {
            r.read_exact(&mut buf[..8])?;
            let expires_timestamp = i64::from_be_bytes(buf);
            Some(
                DateTime::from_timestamp(expires_timestamp, 0)
                    .ok_or(PinsetError::Invalid("invalid expires_at timestamp"))?,
            )
        } else {
            None
        };

        // Read flags (u8)
        r.read_exact(&mut buf[..1])?;
        let flags = match buf[0] {
            0 => PinsetFlags::Active,
            1 => PinsetFlags::Retired,
            2 => PinsetFlags::Tofu,
            _ => return Err(PinsetError::Invalid("unknown flags")),
        };

        Ok(Self {
            peer_id,
            key_type,
            key_data,
            added_at,
            expires_at,
            flags,
        })
    }
}
