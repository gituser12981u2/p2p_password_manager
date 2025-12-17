/*
possible on disk format reference

Header

MAGIC (4 bytes): PVLT
version (u8)
aead_alg (u8)
seq(u64 BE)
vault_id (16 bytes)
nonce (12 bytes)

KDF_PARAMS (32 bytes), // Argon2id parameters for password slot

flags (u8)             // bitmask

[ TLVs ]
TLV: type(u8), len(u16 BE), value([len])

types:
0x01=KEK_LOCATOR,  // OS keystore/device key locator
0x02=WRAP,         // One DEK-wrapping key slot

0x7F=END (Not a TLV)

KDF_PARAMS (32 bytes total):

id (u8)                  // 0x01 = Argon2id
kdf_slot_id (u8)         // small ID for WRAP to reference
salt (16 bytes)
memory_cost_kib (u32 BE) // Argon2 memory cost in KiB
time_cost (u32 BE)       // iterations
parallelism (u32 BE)     // lanes
reserved (u16 BE)        // 0x0000, for future use/padding

KEK_LOCATOR

type = 0x01

value:
  locator_id (u8) //small ID
  locator_len (u16 BE)
  locator ([locator_len])

WRAP

type = 0x02

value:
  slot_id (u8)
  source_kind (u8) // 0x01 = Passpharse, 0x02 = DeviceOsKey

if source_kind == 0x02 (DeviceOSKey):
  locator_id (u8) // KEK_LOCATOR.locator_id

wrap_nonce (N bytes) // N implied by aead_alg
wrapped_dek_len (u16 BE)
wrapped_dek_ct ([wrapped_dek_len])
*/

use bitflags::bitflags;
use std::ffi::OsStr;

pub const MAGIC: [u8; 4] = *b"PVLT";

#[derive(thiserror::Error, Debug)]
pub enum FileError {
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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    AesGcm = 1,
}

impl AeadAlgorithm {
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadAlgorithm::AesGcm => 12, // 96-bit GCM nonces
        }
    }
}

/// Argon2id parameters for password slot
///
/// * `id`: Argon2id
/// * `slot_id`: small ID for WRAP to reference
/// * `salt`:
/// * `memory_cost_kib`: Argon2 memory cost in KiB
/// * `time_cost`: iterations
/// * `parallelism`: lanes
pub struct KdfParams {
    pub id: u8,
    pub slot_id: u8,
    pub salt: [u8; 16],
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub reserved: u16,
}

pub struct KekLocator {
    pub locator_id: u8,
    pub locator: Box<OsStr>,
}

pub struct Wrap {
    pub slot_id: u8,
    pub source_kind: u8, // 0x01 = Passpharse, 0x02 = DeviceOsKey
    pub locator_id: u8,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_dek_len: Vec<u8>,
    pub wrapped_dek_ct: Vec<u8>,
}

bitflags! {
    #[non_exhaustive]
    pub struct Flags: u8 {
        const ACTIVE = 1 << 0;   // 0b00000001
        const RETIRED = 1 << 1;  // 0b00000010
        const TOFU = 1 << 2;     // 0b00000100
        // TODO: Explicitly reserve bits 3-7 for future use
    }
}

impl Flags {
    /// Reserved bits that should not be set in current version
    pub const RESERVED: u8 = 0b1111_1000;

    /// Set a pin record as active, automatically removing retired status
    pub fn set_active(mut self) -> Self {
        self.remove(Flags::RETIRED);
        self.insert(Flags::ACTIVE);
        self
    }

    /// Set a pin record as retired, automatically removing active status
    pub fn set_retired(mut self) -> Self {
        self.remove(Flags::ACTIVE);
        self.insert(Flags::RETIRED);
        self
    }

    /// Check if the pin record is in a valid state (not both active and retired)
    pub fn is_valid(&self) -> bool {
        !(self.contains(Flags::ACTIVE) && self.contains(Flags::RETIRED))
    }
}

pub struct PasswordFileHeader {
    pub version: u8,
    pub aead_alg: AeadAlgorithm,
    pub seq: u64,
    pub vault_id: [u8; 16],
    pub nonce: [u8; 12],
    pub kdf_params: Option<KdfParams>,
    pub flags: Flags,
    pub kek_locators: Vec<KekLocator>,
    pub wraps: Vec<Wrap>,
}

impl PasswordFileHeader {
    pub const fn builder(
        version: u8,
        aead_alg: AeadAlgorithm,
        seq: u64,
        vault_id: [u8; 16],
        nonce: [u8; 12],
    ) -> HeaderBuilder {
        HeaderBuilder {
            version,
            aead_alg,
            seq,
            vault_id,
            nonce,
            kdf_params: None,
            flags: Flags::empty(),
            kek_locators: Vec::new(),
            wraps: Vec::new(),
        }
    }
}

pub struct HeaderBuilder {
    version: u8,
    aead_alg: AeadAlgorithm,
    seq: u64,
    vault_id: [u8; 16],
    nonce: [u8; 12],
    kdf_params: Option<KdfParams>,
    flags: Flags,
    kek_locators: Vec<KekLocator>,
    wraps: Vec<Wrap>,
}

impl HeaderBuilder {
    pub fn kdf_params(mut self, params: KdfParams) -> Self {
        self.kdf_params = Some(params);
        self
    }

    pub fn flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    pub fn add_kek_locator(mut self, locator: KekLocator) -> Self {
        self.kek_locators.push(locator);
        self
    }

    pub fn add_wrap(mut self, wrap: Wrap) -> Self {
        self.wraps.push(wrap);
        self
    }

    pub fn build(self) -> PasswordFileHeader {
        PasswordFileHeader {
            version: self.version,
            aead_alg: self.aead_alg,
            seq: self.seq,
            vault_id: self.vault_id,
            nonce: self.nonce,
            kdf_params: self.kdf_params,
            flags: self.flags,
            kek_locators: self.kek_locators,
            wraps: self.wraps,
        }
    }
}



