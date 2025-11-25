use std::io::{Read, Write};

use crate::pinset::types::{PinsetError, Result};

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

    /// Decode a value from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice to decode from
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or if the data is malformed.
    fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_from(std::io::Cursor::new(bytes))
    }
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
pub(crate) fn write_tlv<W: Write>(mut w: W, t: u8, v: &[u8]) -> Result<()> {
    w.write_all(&[t])?;
    let len = u16::try_from(v.len()).map_err(|_| PinsetError::Invalid("TLV too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(v)?;
    Ok(())
}

/**
 Read exactly `len` bytes from a reader into a new vector.

 # Arguments
  `r`` - The reader to read from
  `len` - The number of bytes to read

 # Errors
 Returns an error if the reader doesn't have enough bytes or if reading fails.
*/
pub(crate) fn read_exact_into<R: Read>(mut r: R, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    Ok(v)
}
