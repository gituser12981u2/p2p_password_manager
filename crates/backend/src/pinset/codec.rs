use crate::pinset::types::{AeadAlgorithm, KeySource, MAGIC, PinsetError, PinsetHeader, Result};
use std::io::{self, Read, Write};

#[inline]
fn be_u16(x: u16) -> [u8; 2] {
    x.to_be_bytes()
}

#[inline]
fn be_u32(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

#[inline]
fn be_u64(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

#[inline]
fn read_exact<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[inline]
fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    Ok(read_exact::<1>(r)?[0])
}

#[inline]
fn read_u16_be(r: &mut impl Read) -> io::Result<u16> {
    Ok(u16::from_be_bytes(read_exact::<2>(r)?))
}

#[inline]
fn read_u32_be(r: &mut impl Read) -> io::Result<u32> {
    Ok(u32::from_be_bytes(read_exact::<4>(r)?))
}

#[inline]
fn read_u64_be(r: &mut impl Read) -> io::Result<u64> {
    Ok(u64::from_be_bytes(read_exact::<8>(r)?))
}

#[inline]
fn read_vec(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0; n];
    r.read_exact(&mut v)?;
    Ok(v)
}

const TLV_END: u8 = 0x7F;

/// Stream a header to any Write sink
pub fn write_header(mut w: impl Write, h: &PinsetHeader) -> Result<()> {
    h.validate()?;

    w.write_all(&MAGIC)?;
    w.write_all(&be_u32(h.version))?;
    w.write_all(&[h.aead_alg as u8])?;
    w.write_all(&[h.key_source as u8])?;
    w.write_all(&be_u64(h.seq))?;
    w.write_all(&be_u16(h.store_id.len() as u16))?;
    w.write_all(&h.store_id)?;
    w.write_all(&[h.nonce.len() as u8])?;
    w.write_all(&h.nonce)?;

    // TODO: Write the optional fields

    w.write_all(&[TLV_END])?;
    Ok(())
}

/// Read a header from any Read source
pub fn read_header(mut r: impl Read) -> Result<PinsetHeader> {
    let magic = read_exact::<4>(&mut r)?;
    if magic != MAGIC {
        return Err(PinsetError::BadMagic);
    }

    let version = read_u32_be(&mut r)?;
    let aead_alg = match read_u8(&mut r)? {
        1 => AeadAlgorithm::AesGcm,
        _ => return Err(PinsetError::Invalid("unknown AEAD algorithm")),
    };
    let key_source = match read_u8(&mut r)? {
        1 => KeySource::OsKeyStore,
        2 => KeySource::PassphraseKdf,
        _ => return Err(PinsetError::Invalid("Unknown key source")),
    };
    let seq = read_u64_be(&mut r)?;
    let store_id = {
        let n = read_u16_be(&mut r)? as usize;
        read_vec(&mut r, n)?
    };
    let nonce = {
        let n = read_u8(&mut r)? as usize;
        read_vec(&mut r, n)?
    };

    // TODO: handle optional TLVs
    let kdf: Option<String> = None;
    let kek_locator: Option<String> = None;
    let wrap: Option<Vec<u8>> = None;

    let header = PinsetHeader {
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

/// Encode a header into a Vec<u8> buffer
pub fn encode_header(h: &PinsetHeader) -> Result<Vec<u8>> {
    let mut v = Vec::with_capacity(8);
    write_header(&mut v, h)?;
    Ok(v)
}

// Decode a header from a byte slice
pub fn decode_header(bytes: &[u8]) -> Result<PinsetHeader> {
    let mut cur = std::io::Cursor::new(bytes);
    read_header(&mut cur)
}

#[cfg(test)]
mod tests {
    use crate::pinset::{
        codec::{decode_header, encode_header, read_header, write_header},
        types::{AeadAlgorithm, KeySource, PinsetHeader},
    };
    use std::io::Cursor;

    #[test]
    fn round_trip_streaming() {
        let version = 1;
        let store_id = b"store-01";
        let nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];
        let header = PinsetHeader::builder(
            version,
            AeadAlgorithm::AesGcm,
            KeySource::OsKeyStore,
            store_id.to_vec(),
            nonce,
        )
        .build()
        .unwrap();
        let mut buf = Vec::new();

        // write/read via streaming API
        write_header(&mut buf, &header).expect("write_header");
        let read_back = read_header(Cursor::new(&buf)).expect("read_header");
        assert_eq!(read_back, header);
    }

    #[test]
    fn round_trip_buffered() {
        let version = 1;
        let store_id = b"store-01";
        let nonce = vec![0u8; AeadAlgorithm::AesGcm.nonce_len()];
        let header = PinsetHeader::builder(
            version,
            AeadAlgorithm::AesGcm,
            KeySource::OsKeyStore,
            store_id.to_vec(),
            nonce,
        )
        .build()
        .unwrap();
        let bytes = encode_header(&header).expect("encode_header");
        let read_back = decode_header(&bytes).expect("decode_header");
        assert_eq!(read_back, header)
    }

    // TODO: Add more tests
}
