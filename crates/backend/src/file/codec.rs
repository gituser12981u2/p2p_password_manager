use std::io::Write;

use crate::{
    codec::{TlvDecode, TlvEncode, write_tlv},
    file::types::{Flags, KdfParams, MAGIC, PasswordFileHeader, Wrap},
    pinset::types::{Result, PinsetError},
};


const TLV_KEK_LOCATOR: u8 = 0x01;
const TLV_WRAP: u8 = 0x02;
const TLV_END: u8 = 0x7F;

impl TlvEncode for KdfParams {
    fn encode_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&[self.id])?;
        w.write_all(&[self.slot_id])?;
        w.write_all(&self.salt)?;
        w.write_all(&self.memory_cost_kib.to_be_bytes())?;
        w.write_all(&self.time_cost.to_be_bytes())?;
        w.write_all(&self.parallelism.to_be_bytes())?;
        w.write_all(&self.reserved.to_be_bytes())?;
        Ok(())
    }
}

impl TlvDecode for KdfParams {
    fn decode_from<R: std::io::Read>(mut r: R) -> crate::pinset::types::Result<Self> {
        let mut id = [0u8; 1];
        let mut salt = [0u8; 16];
        let mut slot_id = [0u8; 1];
        let mut memory_cost_kib = [0u8; 4];  
        let mut time_cost = [0u8; 4];  
        let mut parallelism = [0u8; 4];  
        let mut reserved = [0u8; 2];  

        r.read_exact(&mut id)?;
        r.read_exact(&mut salt)?;
        r.read_exact(&mut slot_id)?;
        r.read_exact(&mut memory_cost_kib)?;
        r.read_exact(&mut time_cost)?;
        r.read_exact(&mut parallelism)?;
        r.read_exact(&mut reserved)?;

        Ok(KdfParams {
            id: id[0],
            slot_id: slot_id[0],
            salt,
            memory_cost_kib: u32::from_be_bytes(memory_cost_kib),
            time_cost: u32::from_be_bytes(time_cost),
            parallelism: u32::from_be_bytes(parallelism),
            reserved: u16::from_be_bytes(reserved),
        })
    }
}

impl TlvEncode for Wrap {
    fn encode_to<W: std::io::Write>(&self, mut w: W) -> crate::pinset::types::Result<()> {
        w.write_all(&[self.slot_id])?;
        w.write_all(&[self.source_kind])?;

        if self.source_kind == 0x02 {
            // DeviceOsKey requires locator_id
            w.write_all(&[self.locator_id])?;
        }

        // wrap_nonce (N bytes; N depends on aead_alg and is inferred from length)
        w.write_all(&self.wrap_nonce)?;
        w.write_all(&self.wrapped_dek_len)?;
        w.write_all(&self.wrapped_dek_ct)?;

        Ok(())
    }
}

impl TlvDecode for Wrap {
    fn decode_from<R: std::io::Read>(mut r: R) -> crate::pinset::types::Result<Self> {
        todo!()
    }
}

pub fn encode_header<W: Write>(
    mut w: W,
    header: &PasswordFileHeader,
    flags: Flags,
    wraps: &[Wrap],
) -> Result<()> {

    w.write_all(&MAGIC)?;
    w.write_all(&header.version.to_be_bytes())?;
    w.write_all(&[header.aead_alg as u8])?;
    w.write_all(&header.seq.to_be_bytes())?;
    w.write_all(&header.vault_id)?;
    w.write_all(&header.nonce)?;

    if let Some(params) = header.kdf_params {
        w.write_all(&[params.id])?;
        w.write_all(&[params.slot_id])?;
        w.write_all(&params.salt)?;
        w.write_all(&[params.time_cost as u8])?;
        w.write_all(&[params.memory_cost_kib as u8])?;
        w.write_all(&[params.parallelism as u8])?;
        w.write_all(&[params.reserved as u8])?;
    } 

    w.write_all(
        &[flags.bits()]
    )?;

    if let Some(kek) = header.kek_locators {
        write_tlv(w, TLV_KEK_LOCATOR, kek);
    }


    // TODO Write the TLVs
    // TLVs
    //
    // 0x01 - KEK_LOCATOR - optional
    // 0x02 - WRAP (zero or more)

    // TODO Write 0x7F End marker
}

pub fn decode_header<R: std::io::Read>(
    mut r: R,
) -> crate::pinset::types::Result<PasswordFileHeader> {
    todo!()

    // TODO Read and check the MAGIC

    // TODO Read the header fields (version, aead_alg, seq, vault_id, and nonce)
    // TODO Read the kdf_params, flags, and loop through the TLVs to read them
}
