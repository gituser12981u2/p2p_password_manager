use crate::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, MAGIC, PinsetError, PinsetFlags, PinsetHeader, PinsetRecord,
    Result,
};
use chrono::DateTime;
use std::io::{Read, Write};
use zeroize::Zeroizing;

const TLV_KDF: u8 = 0x01;
const TLV_KEK_LOCATOR: u8 = 0x02;
const TLV_WRAP: u8 = 0x03;
const TLV_END: u8 = 0x7F;

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

fn write_tlv<W: Write>(mut w: W, t: u8, v: &[u8]) -> Result<()> {
    w.write_all(&[t])?;
    let len = u16::try_from(v.len()).map_err(|_| PinsetError::Invalid("TLV too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(v)?;
    Ok(())
}

fn read_exact_into<R: Read>(mut r: R, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    Ok(v)
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

        // Optional TLVs
        if let Some(kdf) = &self.kdf {
            write_tlv(&mut w, TLV_KDF, kdf.as_bytes())?;
        }
        if let Some(kek) = &self.kek_locator {
            write_tlv(&mut w, TLV_KEK_LOCATOR, kek.as_bytes())?;
        }
        if let Some(wrap) = &self.wrap {
            write_tlv(&mut w, TLV_WRAP, wrap.as_ref())?;
        }

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

        let mut buf1 = [0u8; 1];
        r.read_exact(&mut buf1)?;
        let version = u8::from_be_bytes(buf1);

        r.read_exact(&mut buf1)?;
        let aead_alg = match buf1[0] {
            1 => AeadAlgorithm::AesGcm,
            _ => return Err(PinsetError::Invalid("unknown AEAD algorithm")),
        };

        r.read_exact(&mut buf1)?;
        let key_source = match buf1[0] {
            1 => KeySource::OsKeyStore,
            2 => KeySource::PassphraseKdf,
            _ => return Err(PinsetError::Invalid("Unknown key source")),
        };

        let mut buf8 = [0u8; 8];
        r.read_exact(&mut buf8)?;
        let seq = u64::from_be_bytes(buf8);

        let mut store_id = [0u8; 16];
        r.read_exact(&mut store_id)?;

        let mut nonce = [0u8; 12];
        r.read_exact(&mut nonce)?;

        let mut kdf: Option<Box<str>> = None;
        let mut kek_locator: Option<Box<str>> = None;
        let mut wrap: Option<Zeroizing<Box<[u8]>>> = None;

        loop {
            r.read_exact(&mut buf1)?;
            let tag = buf1[0];
            if tag == TLV_END {
                break;
            }

            // length
            let mut buf2 = [0u8; 2];
            r.read_exact(&mut buf2)?;
            let len = u16::from_be_bytes(buf2) as usize;

            match tag {
                TLV_KDF => {
                    let v = read_exact_into(&mut r, len)?;
                    let s = std::str::from_utf8(&v)
                        .map_err(|_| PinsetError::Invalid("kdf not valid utf-8"))?;
                    kdf = Some(s.into())
                }
                TLV_KEK_LOCATOR => {
                    let v = read_exact_into(&mut r, len)?;
                    let s = std::str::from_utf8(&v)
                        .map_err(|_| PinsetError::Invalid("kek_locator not valid utf-8"))?;
                    kek_locator = Some(s.into())
                }
                TLV_WRAP => {
                    let v = read_exact_into(&mut r, len)?;
                    wrap = Some(Zeroizing::from(v.into_boxed_slice()));
                }
                _ => return Err(PinsetError::Invalid("unknown TLV tag")),
            }
        }

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
        w.write_all(&32u16.to_be_bytes())?;
        w.write_all(&self.peer_id)?;

        // Write key_type (u8)
        w.write_all(&[self.key_type as u8])?;

        let key_len = u16::try_from(self.key_data.len())
            .map_err(|_| PinsetError::Invalid("key_data too long"))?;

        w.write_all(&key_len.to_be_bytes())?;
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
        let flags_byte = match () {
            _ if self.flags.contains(PinsetFlags::ACTIVE) => 0,
            _ if self.flags.contains(PinsetFlags::RETIRED) => 1,
            _ if self.flags.contains(PinsetFlags::TOFU) => 2,
            _ => 0, // Default to active
        };
        w.write_all(&[flags_byte])?;

        Ok(())
    }
}

impl TlvDecode for PinsetRecord {
    fn decode_from<R: Read>(mut r: R) -> Result<Self> {
        let mut buf = [0u8; 8]; // big enough for the largest read

        // Read peer_id_len (u16) + peer_id - expect exactly 32 bytes
        r.read_exact(&mut buf[..2])?;
        let peer_id_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if peer_id_len != 32 {
            return Err(PinsetError::Invalid("peer_id must be exactly 32 bytes"));
        }
        let mut peer_id = [0u8; 32];
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
            0 => PinsetFlags::ACTIVE,
            1 => PinsetFlags::RETIRED,
            2 => PinsetFlags::TOFU,
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
