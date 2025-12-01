use std::io::Write;

use crate::{
    codec::{TlvDecode, TlvEncode},
    file::types::{Flags, KdfParams, PasswordFileHeader, Wrap},
    pinset::types::Result,
};

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

        r.read_exact(&mut id)?;
        // TODO: implement reading of the slot_id, salt, memory_cost_kib, time_cost, and parallelism

        Ok(KdfParams {
            id: id[0],
            slot_id: todo!(),
            salt: todo!(),
            memory_cost_kib: todo!(),
            time_cost: todo!(),
            parallelism: todo!(),
            reserved: todo!(),
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

        // TODO Write wrapped_dek_len and wrapped_dek_ct

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
    todo!()

    // TODO Write the MAGIC
    // TODO Write the header fields (version, aead_alg, seq, vault_id, and nonce)

    // TODO Write the kdf params

    // TODO Write the flags

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
