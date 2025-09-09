

use serde::{Deserialize, Serialize};

const MAGIC:[u8;4]=*b"PSET";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType { //Change this as needed, we can easily add appropriate impl's on.
    Ed25519,
    Spki,
    PqHybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PinsetFlags {
    Active,
    Retired,
    Tofu, //I'm not googling this, too tired.
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AeadAlgorithm {
    AesGcm, //Add others as appropriate
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeySource {
    OsKeyStore, //As above
    PassphraseKdf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetRecord {
    pub peer_id: Vec<u8>,
    pub key_type: KeyType,
    pub key_data: Vec<u8>,
    pub added_at: u64,
    pub expires_at: Option<u64>,
    pub flags: PinsetFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetStore {
    pub records: Vec<PinsetRecord>,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub aead_alg: AeadAlgorithm,
    pub key_source: KeySource,
    pub kdf: Option<String>,
    pub kek_locator: Option<String>, //This needs to be changed at some point
    pub store_id: Vec<u8>, // This can probablyy
    pub seq: u64,
    pub nonce: Vec<u8>,
    pub wrap: Option<Vec<u8>>,
}

/*

referemce for myself
magic number (i.e "pinsetstore" or "PSET")
version
aead_alg (Probably AES-GCM)
key_source (OSKeyStore, PassphraseKDF)
kdf (optional for passphrase mode)
kek_locator (optional for OS key store mode)
store_id (salt for KEK)
seq (increments each save and used for unique nonce making)
nonce (for AES-GCM)
wrap (optional wrap FESK under a KEK)

*/

impl PinsetHeader {
    pub const fn new( //Make this into a builder pattern?
        version: u32,
        aead_alg: AeadAlgorithm,
        key_source: KeySource,
        store_id: Vec<u8>,
        seq: u64,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            magic: MAGIC, //This structure doesn't seem right.
            version,
            aead_alg,
            key_source,
            kdf: None,
            kek_locator: None,
            store_id,
            seq,
            nonce,
            wrap: None,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {  // Add some error handling here tommorrow
        if self.magic != MAGIC {
            return Err("Invalid magic number");
        }
        if self.nonce.len() != 12 {  // GCM nonce size
            return Err("Invalid nonce length");
        }
        Ok(())
    }
}

impl PinsetStore {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            version: 1,
        }
    }

    pub fn find_by_peer_id(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn cleanup_expired(&mut self, current_time: u64) {
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
            .filter(|r| matches!(r.flags, PinsetFlags::Active))
            .collect()
    }
}

impl PinsetRecord {
    pub const fn new(
        peer_id: Vec<u8>,
        key_type: KeyType,
        key_data: Vec<u8>,
        added_at: u64, //change this into POSIX times FIXME (use chrono or jiff!)
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

    pub const fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub  fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at.is_some_and( |exp| current_time > exp) //Make these into POSIX times FIXME
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.flags, PinsetFlags::Active)
    }
}

