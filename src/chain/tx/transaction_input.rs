use byte::{BytesExt, LE, TryRead};
use byte::ctx::Endian;
use hashes::hex::ToHex;
use crate::crypto::{UInt256, VarBytes};
use crate::crypto::byte_util::BytesDecodable;
use crate::crypto::utxo::UTXO;
use crate::impl_bytes_decodable;
// use crate::storage::models::tx::transaction_input::TransactionInputEntity;
use crate::util::data_append::DataAppend;

#[derive(Clone, Default, PartialEq)]
pub struct TransactionInput {
    pub input_hash: UInt256,
    pub index: u32,
    pub script: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub sequence: u32,
}
impl_bytes_decodable!(TransactionInput);

impl std::fmt::Debug for TransactionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionInput")
            .field("input_hash", &self.input_hash)
            .field("index", &self.index)
            .field(
                "script",
                &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_hex(),
            )
            .field(
                "signature",
                &self
                    .signature
                    .as_ref()
                    .unwrap_or(&Vec::<u8>::new())
                    .to_hex(),
            )
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl<'a> TryRead<'a, Endian> for TransactionInput {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let index = bytes.read_with::<u32>(offset, LE)?;
        let signature = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1.to_vec()),
            Err(_err) => None,
        };
        let sequence = bytes.read_with::<u32>(offset, LE)?;
        let input = TransactionInput {
            input_hash,
            index,
            script: None,
            signature,
            sequence,
        };
        Ok((input, *offset))
    }
}

impl TransactionInput {
    pub fn coinbase(identifier: &String, version: u16, protocol_version: u32) -> Self {
        TransactionInput {
            index: u32::MAX,
            signature: Some(Vec::<u8>::devnet_genesis_coinbase_message(identifier, version, protocol_version)),
            sequence: u32::MAX,
            ..Default::default()
        }
    }

    /*pub fn from_entity(entity: TransactionInputEntity) -> Self {
        Self {
            input_hash: entity.tx_hash,
            index: entity.n as u32,
            script: None,
            signature: Some(entity.signature),
            sequence: entity.sequence as u32
        }
    }*/

    pub fn outpoint(&self) -> UTXO {
        UTXO { hash: self.input_hash, n: self.index }
    }
}
