/*!
 Codec for encoding and decoding pinset data structures.

 This module implements TLV (Type-Length-Value) encoding/decoding for pinset headers
 and records, providing a binary serialization format for secure storage of peer
 identity pinning information.
*/

use crate::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, MAGIC, PinsetError, PinsetFlags, PinsetHeader, PinsetRecord,
    Result,
};
use chrono::DateTime;
use std::ffi::OsStr;
use std::io::{Read, Write};
use zeroize::Zeroizing;

// TLV tag constants for optional header fields
/// Tag for KDF (Key Derivation Function) parameter
const TLV_KDF: u8 = 0x01;
/// Tag for KEK (Key Encryption Key) locator
const TLV_KEK_LOCATOR: u8 = 0x02;
/// Tag for wrapped encryption key
const TLV_WRAP: u8 = 0x03;
/// Tag marking end of TLV section
/// Tag marking end of TLV section
const TLV_END: u8 = 0x7F;

/**  Trait for encoding data structures into TLV binary format.

 Implementers can serialize themselves to a writer or to a byte vector.
*/
pub(crate) trait TlvEncode {
    /**
     Encode this value to the provided writer.

     # Arguments
     `w` - The writer to encode into

     # Errors
     Returns an error if writing fails or if the data is invalid.
    */
    fn encode_to<W: Write>(&self, w: W) -> Result<()>;

    /**
     Encode this value to a new byte vector.

     # Errors
     Returns an error if encoding fails or if the data is invalid.
    */
    fn encode(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.encode_to(&mut v)?;
        Ok(v)
    }
}

/** Trait for decoding data structures from TLV binary format.

 Implementers can deserialize themselves from a reader or from a byte slice.
*/
pub(crate) trait TlvDecode: Sized {
    /**
     Decode a value from the provided reader.

     # Arguments
      `r` - The reader to decode from

     # Errors
     Returns an error if reading fails or if the data is malformed.
    */
    fn decode_from<R: Read>(r: R) -> Result<Self>;

    /** Decode a value from a byte slice.

     # Arguments
      `bytes` - The byte slice to decode from

     # Errors
     Returns an error if decoding fails or if the data is malformed.
    */
    fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_from(std::io::Cursor::new(bytes))
    }
}

pub(crate) struct PinsetBody {
    pub records: Vec<PinsetRecord>,
}

/**
 Write a TLV (Type-Length-Value) triple to a writer.

 # Arguments
 * `w` - The writer to write to
 * `t` - The tag byte identifying the field type
 * `v` - The value bytes to write

 # Format
 - 1 byte: tag
 - 2 bytes: length (big-endian u16)
 - N bytes: value

 # Errors
 Returns an error if the value is too long (>65535 bytes) or if writing fails.
*/
fn write_tlv<W: Write>(mut w: W, t: u8, v: &[u8]) -> Result<()> {
    w.write_all(&[t])?;
    let len = u16::try_from(v.len()).map_err(|_| PinsetError::Invalid("TLV too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(v)?;
    Ok(())
}

/**
 Read exactly `len` bytes from a reader into a new vector.

 # Arguments
  `r` - The reader to read from
  `len` - The number of bytes to read

 # Errors
 Returns an error if the reader doesn't have enough bytes or if reading fails.
*/
fn read_exact_into<R: Read>(mut r: R, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    Ok(v)
}

/**
 Encode a PinsetHeader to binary format.

 # Format
 - 4 bytes: magic number
 - 1 byte: version
 - 1 byte: AEAD algorithm identifier
 - 1 byte: key source identifier
 - 8 bytes: sequence number (big-endian)
 - 16 bytes: store ID
 - 12 bytes: nonce
 - TLV section: optional fields (KDF, KEK locator, wrap)
 - 1 byte: TLV_END marker
*/
impl TlvEncode for PinsetHeader {
    fn encode_to<W: Write>(&self, mut w: W) -> Result<()> {
        // Validate header before encoding
        self.validate()?;

        // Write fixed-size header fields
        w.write_all(&MAGIC)?;
        w.write_all(&self.version.to_be_bytes())?;
        w.write_all(&[self.aead_alg as u8])?;
        w.write_all(&[self.key_source as u8])?;
        w.write_all(&self.seq.to_be_bytes())?;
        w.write_all(&self.store_id)?;
        w.write_all(&self.nonce)?;

        // Write optional TLV fields
        if let Some(kdf) = &self.kdf {
            write_tlv(&mut w, TLV_KDF, kdf.as_bytes())?;
        }
        if let Some(kek) = &self.kek_locator {
            write_tlv(&mut w, TLV_KEK_LOCATOR, kek.as_encoded_bytes())?;
        }
        if let Some(wrap) = &self.wrap {
            write_tlv(&mut w, TLV_WRAP, wrap.as_ref())?;
        }

        // Write TLV end marker
        w.write_all(&[TLV_END])?;
        Ok(())
    }
}

/**
  Decode a PinsetHeader from binary format.

 Reads and validates all header fields, including optional TLV-encoded fields.
 The header format must match the encoding specified in `TlvEncode for PinsetHeader`.
*/
impl TlvDecode for PinsetHeader {
    fn decode_from<R: Read>(mut r: R) -> Result<Self> {
        // Read and verify magic number
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(PinsetError::BadMagic);
        }

        // Read version
        let mut buf1 = [0u8; 1];
        r.read_exact(&mut buf1)?;
        let version = u8::from_be_bytes(buf1);

        // Read and parse AEAD algorithm
        r.read_exact(&mut buf1)?;
        let aead_alg = match buf1[0] {
            1 => AeadAlgorithm::AesGcm,
            _ => return Err(PinsetError::Invalid("unknown AEAD algorithm")),
        };

        // Read and parse key source
        r.read_exact(&mut buf1)?;
        let key_source = match buf1[0] {
            1 => KeySource::OsKeyStore,
            2 => KeySource::PassphraseKdf,
            _ => return Err(PinsetError::Invalid("Unknown key source")),
        };

        // Read sequence number
        let mut buf8 = [0u8; 8];
        r.read_exact(&mut buf8)?;
        let seq = u64::from_be_bytes(buf8);

        // Read store ID (16 bytes)
        let mut store_id = [0u8; 16];
        r.read_exact(&mut store_id)?;

        // Read nonce (12 bytes)
        let mut nonce = [0u8; 12];
        r.read_exact(&mut nonce)?;

        // Initialise optional fields
        let mut kdf: Option<Box<str>> = None;
        let mut kek_locator: Option<Box<OsStr>> = None;
        let mut wrap: Option<Zeroizing<Box<[u8]>>> = None;

        // Read TLV section for optional fields
        loop {
            r.read_exact(&mut buf1)?;
            let tag = buf1[0];
            if tag == TLV_END {
                break;
            }

            // Read length (2 bytes, big-endian)
            let mut buf2 = [0u8; 2];
            r.read_exact(&mut buf2)?;
            let len = u16::from_be_bytes(buf2) as usize;

            // Parse based on tag
            match tag {
                TLV_KDF => {
                    let v = read_exact_into(&mut r, len)?;
                    let s = std::str::from_utf8(&v)
                        .map_err(|_| PinsetError::Invalid("kdf not valid utf-8"))?;
                    kdf = Some(s.into())
                }
                TLV_KEK_LOCATOR => {
                    let v = read_exact_into(&mut r, len)?;
                    // SAFETY: The OsStr was written as encoded, therefore it can be read as encoded.
                    kek_locator = unsafe { Some(OsStr::from_encoded_bytes_unchecked(&v).into()) };
                }
                TLV_WRAP => {
                    let v = read_exact_into(&mut r, len)?;
                    wrap = Some(Zeroizing::from(v.into_boxed_slice()));
                }
                _ => return Err(PinsetError::Invalid("unknown TLV tag")),
            }
        }

        // Construct and validate header
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

impl TlvEncode for PinsetBody {
    fn encode_to<W: Write>(&self, mut w: W) -> Result<()> {
        let count = u32::try_from(self.records.len())
            .map_err(|_| PinsetError::Invalid("Too many records "))?;
        w.write_all(&count.to_be_bytes())?;
        for rec in &self.records {
            rec.write_tlv(&mut w)?;
        }
        Ok(())
    }
}

impl TlvDecode for PinsetBody {
    fn decode_from<R: Read>(mut r: R) -> Result<Self> {
        let mut count_bytes = [0u8; 4];
        r.read_exact(&mut count_bytes)?;
        let count = u32::from_be_bytes(count_bytes) as usize;

        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(PinsetRecord::read_tlv(&mut r)?);
        }
        Ok(Self { records })
    }
}

/**
 Encode a PinsetRecord to binary format.

 # Format
 - 2 bytes: peer_id length (always 32, big-endian)
 - 32 bytes: peer_id
 - 1 byte: key_type identifier
 - 2 bytes: key_data length (big-endian)
 - N bytes: key_data
 - 8 bytes: added_at timestamp (Unix timestamp, big-endian)
 - 1 byte: has_expires flag (0 or 1)
 - 8 bytes: expires_at timestamp (only if has_expires=1, Unix timestamp, big-endian)
 - 1 byte: flags bitfield
*/
impl TlvEncode for PinsetRecord {
    fn encode_to<W: Write>(&self, mut w: W) -> Result<()> {
        // Write peer_id length and data (fixed 32 bytes)
        w.write_all(&32u16.to_be_bytes())?;
        w.write_all(&self.peer_id)?;

        // Write key_type (u8)
        w.write_all(&[self.key_type as u8])?;

        // Write key_data length and data
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

        // Write flags bitfield
        w.write_all(&[self.flags.bits()])?;

        Ok(())
    }
}

/**
 Decode a PinsetRecord from binary format.

 Reads and validates all record fields. The format must match the encoding
 specified in `TlvEncode for PinsetRecord`.
*/
impl TlvDecode for PinsetRecord {
    fn decode_from<R: Read>(mut r: R) -> Result<Self> {
        let mut buf = [0u8; 8]; // Reusable buffer, sized for largest read

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

        // Read has_expires flag (u8 0/1) + expires_at (u64 BE if present)
        r.read_exact(&mut buf[..1])?;
        let expires_at = if buf[0] == 1 {
            // Read expires_at timestamp
            r.read_exact(&mut buf[..8])?;
            let expires_timestamp = i64::from_be_bytes(buf);
            Some(
                DateTime::from_timestamp(expires_timestamp, 0)
                    .ok_or(PinsetError::Invalid("invalid expires_at timestamp"))?,
            )
        } else {
            None
        };

        // Read flags bitfield (u8)
        r.read_exact(&mut buf[..1])?;
        let flags =
            PinsetFlags::from_bits(buf[0]).ok_or(PinsetError::Invalid("invalid flags bits"))?;

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
