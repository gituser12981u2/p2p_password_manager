/*
possible on disk format reference

Header

MAGIC (4 bytes): PVLT
version (u8)
aead_alg (u8)
seq(u64 BE)
valut_id (16 bytes)
nonce (12 bytes)

KDF_PARAMS (32 bytes), // Argon2id parameters for password slot 

flags (u8)                         // bitmask

[ TLVs ]
TLV: type(u8), len(u16 BE), value([len])

types: 
0x01=KEK_LOCATOR,  // OS keystore/device key locator
0x02=WRAP,  // One DEK-wrapping key slot


0x7F=END (Not a TLV, sorry if the formatting of this message makes it look like it is) 


KDF_PARAMS (32 bytes total):

id (u8) // 0x01 = Argon2id
kdf_slot_id (u8) // small ID for WRAP to reference
salt (16 bytes)
memory_cost_kib (u32 BE) //Argon2 memory cost in KiB
time_cost (u32 BE) // iterations
parallelism (u32 BE) // lanes
reserved (u16 BE) //0x0000, for future use/padding

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

flags (u8)
*/


use bitflags::bitflags;
use std::ffi::OsStr;

pub const MAGIC: [u8; 4] = *b"PLVT";


pub struct FileHeader {
    pub version: u8,
    pub aead_alg: u8,
    pub kdf: Option<Box<str>>,
    pub kek_locator: Option<Box<OsStr>>,
    pub seq: u64,
    pub valut_id: [u8; 16],
    pub nonce: [u8; 12], 
    pub kdf_params: Option<KdfParams>, 
}

impl FileHeader {
    pub const fn builder(
        version: u8,
        aead_alg: u8,
        valut_id: [u8; 16],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            version,
            aead_alg,
            kdf_params: None,
            kek_locator: None,
            valut_id,
            kdf: None,
            seq: 0,
            nonce,
        }
    }
}


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


/// Argon2id parameters for password slot 
///
/// * `id`: Argon2id
/// * `slot_id`: small ID for WRAP to reference
/// * `salt`: 
/// * `memory_cost_kib`: Argon2 memory cost in KiB
/// * `time_cost`: iterations
/// * `parallelism`: lanes
pub struct KdfParams {
    id: u8, 
    slot_id: u8,
    salt: [u8; 16], 
    memory_cost_kib: u32, 
    time_cost: u32,
    parallelism: u32, 
    reserved: u16,
}


bitflags!{
    pub struct Flags: u8 {
        const ACTIVE = 1 << 0;  // 0b00000001
        const RETIRED = 1 << 1;  // 0b00000010
        const TOFU = 1 << 2;  // 0b00000100
    }
}


struct Wrap {
    slot_id: u8,
    source_kind: u8, // 0x01 = Passpharse, 0x02 = DeviceOsKey
    locator_id: u8,
    wrap_nonce: Vec<u8>,
    wrapped_dek_len: Vec<u8>, 
    wrapped_dek_ct: Vec<u8>
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

