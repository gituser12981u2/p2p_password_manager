use crate::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, MAGIC, PinsetError, PinsetFlags, PinsetHeader, PinsetRecord,
    Result,
};
use chrono::DateTime;
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub trait TlvEncode {
    fn encode_to<W: Write>(&self, w: W) -> Result<()>;
    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.encode_to(&mut v)?;
        Ok(v)
    }
}

pub trait TlvDecode: Sized {
    fn decode_from<R: Read>(r: R) -> Result<Self>;
    fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_from(std::io::Cursor::new(bytes))
    }
}

impl TlvEncode for PinsetHeader {
    fn encode_to<W: Write>(&self, mut w: W) -> Result<()> {
        self.validate()?;

        w.write_all(&MAGIC)?;
        w.write_all(&self.version.to_be_bytes())?;
        w.write_all(&[self.aead_alg as u8])?;
        w.write_all(&[self.key_source as u8])?;
        w.write_all(&self.seq.to_be_bytes())?;
        w.write_all(&self.store_id)?;
        w.write_all(&self.nonce)?;

        // TODO: Write the optional fields (kdf, kek_locator, wrap)

        const TLV_END: u8 = 0x7F;
        w.write_all(&[TLV_END])?;
        Ok(())
    }
}

impl TlvDecode for PinsetHeader {
    fn decode_from<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(PinsetError::BadMagic);
        }

        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        let version = u8::from_be_bytes(buf);

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

        let mut store_id = [0u8; 16];
        r.read_exact(&mut store_id)?;

        let mut nonce = [0u8; 12];
        r.read_exact(&mut nonce)?;

        // TODO: handle optional TLVs until END
        let kdf: Option<String> = None;
        let kek_locator: Option<String> = None;
        let wrap: Option<Zeroizing<Box<[u8]>>> = None;

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
}

impl TlvEncode for PinsetRecord {
    fn encode_to<W: Write>(&self, mut w: W) -> Result<()> {
        // Write peer_id_len (u16) + peer_id
        w.write_all(&(self.peer_id.len() as u16).to_be_bytes())?;
        w.write_all(&self.peer_id)?; //We could be more specific with error handling on write

        // Write key_type (u8)
        w.write_all(&[self.key_type as u8])?;

        // Write key_len (u16) + key_data
        w.write_all(&(self.key_data.len() as u16).to_be_bytes())?;
        w.write_all(self.key_data.as_ref())?;

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
}

impl TlvDecode for PinsetRecord {
    fn decode_from<R: Read>(mut r: R) -> Result<Self> {
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
        let mut key_vec = vec![0; key_len];
        r.read_exact(&mut key_vec)?;
        let key_data = Zeroizing::from(key_vec.into_boxed_slice());

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

#[cfg(test)]
mod tests;
