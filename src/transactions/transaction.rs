use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use dash_spv_primitives::consensus::Encodable;
use dash_spv_primitives::consensus::encode::{consensus_encode_with_size, VarInt};
use dash_spv_primitives::crypto::byte_util::{UInt256, VarBytes};
use dash_spv_primitives::hashes::{Hash, sha256d};
use crate::transactions::transaction::TransactionType::Classic;

// block height indicating transaction is unconfirmed
pub const TX_UNCONFIRMED: i32 = i32::MAX;

pub static SIGHASH_ALL: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TransactionType {
    Classic = 0,
    ProviderRegistration = 1,
    ProviderUpdateService = 2,
    ProviderUpdateRegistrar = 3,
    ProviderUpdateRevocation = 4,
    Coinbase = 5,
    QuorumCommitment = 6,
    SubscriptionRegistration = 8,
    SubscriptionTopUp = 9,
    SubscriptionResetKey = 10,
    SubscriptionCloseAccount = 11,
    Transition = 12,
}

impl From<u16> for TransactionType {
    fn from(orig: u16) -> Self {
        match orig {
            0x0000 => TransactionType::Classic,
            0x0001 => TransactionType::ProviderRegistration,
            0x0002 => TransactionType::ProviderUpdateService,
            0x0003 => TransactionType::ProviderUpdateRegistrar,
            0x0004 => TransactionType::ProviderUpdateRevocation,
            0x0005 => TransactionType::Coinbase,
            0x0006 => TransactionType::QuorumCommitment,
            0x0008 => TransactionType::SubscriptionRegistration,
            0x0009 => TransactionType::SubscriptionTopUp,
            0x000A => TransactionType::SubscriptionResetKey,
            0x000B => TransactionType::SubscriptionCloseAccount,
            0x000C => TransactionType::Transition,
            _ => TransactionType::Classic
        }
    }
}

impl Into<u16> for TransactionType {
    fn into(self) -> u16 {
        *&self as u16
    }
}

impl TransactionType {
    fn raw_value(&self) -> u16 {
        *self as u16
    }
    pub fn requires_inputs(&self) -> bool { true }
}

#[derive(Clone, Copy, Debug)]
pub struct TransactionInput<'a> {
    pub input_hash: UInt256,
    pub index: u32,
    pub script: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub sequence: u32,
}

impl<'a> TryRead<'a, Endian> for TransactionInput<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let index = bytes.read_with::<u32>(offset, LE)?;
        let signature = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1),
            Err(_err) => None
        };
        let sequence = bytes.read_with::<u32>(offset, LE)?;
        let input = TransactionInput {
            input_hash,
            index,
            script: None,
            signature,
            sequence
        };
        Ok((input, *offset))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TransactionOutput<'a> {
    pub amount: u64,
    pub script: Option<&'a [u8]>,
    pub address: Option<&'a [u8]>,
}

impl<'a> TryRead<'a, Endian> for TransactionOutput<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let amount = bytes.read_with::<u64>(offset, LE)?;
        let script = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1),
            Err(_err) => None
        };
        let output = TransactionOutput { amount, script, address: None };
        Ok((output, *offset))
    }
}


pub trait ITransaction {
    fn payload_data(&self) -> Vec<u8>;
    fn payload_data_for(&self) -> Vec<u8>;
    fn transaction_type(&self) -> TransactionType;
}

#[derive(Debug)]
pub struct Transaction<'a> {

    pub inputs: Vec<TransactionInput<'a>>,
    pub outputs: Vec<TransactionOutput<'a>>,

    pub lock_time: u32,
    pub version: u16,
    pub tx_hash: Option<UInt256>,
    pub tx_type: TransactionType,

    pub payload_offset: usize,
    pub block_height: u32,
}

impl<'a> Transaction<'a> {

    pub fn to_data(&self) -> Vec<u8> {
        self.to_data_with_subscript_index(u64::MAX)
    }

    pub fn to_data_with_subscript_index(&self, subscript_index: u64) -> Vec<u8> {
        Self::data_with_subscript_index_static(
            subscript_index,
            self.version,
            self.tx_type,
            &self.inputs,
            &self.outputs, self.lock_time)
    }

    pub fn data_with_subscript_index_static(
        subscript_index: u64,
        version: u16,
        tx_type: TransactionType,
        inputs: &Vec<TransactionInput>,
        outputs: &Vec<TransactionOutput>,
        lock_time: u32,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let inputs_len = inputs.len();
        let outputs_len = outputs.len();
        *offset += version.consensus_encode(&mut buffer).unwrap();
        *offset += tx_type.raw_value().consensus_encode(&mut buffer).unwrap();
        *offset += VarInt(inputs_len as u64).consensus_encode(&mut buffer).unwrap();
        (0..inputs_len).into_iter().for_each(|i| {
            let input = &inputs[i];
            *offset += input.input_hash.consensus_encode(&mut buffer).unwrap();
            *offset += input.index.consensus_encode(&mut buffer).unwrap();
            if subscript_index == u64::MAX && input.signature.is_some() {
                *offset += consensus_encode_with_size(input.signature.unwrap(), &mut buffer).unwrap()
            } else if subscript_index == i as u64 && input.script.is_some() {
                *offset += consensus_encode_with_size(input.script.unwrap(), &mut buffer).unwrap()
            } else {
                *offset += VarInt(0 as u64).consensus_encode(&mut buffer).unwrap();
            }
            *offset += input.sequence.consensus_encode(&mut buffer).unwrap();
        });
        *offset += VarInt(outputs_len as u64).consensus_encode(&mut buffer).unwrap();
        (0..outputs_len).into_iter().for_each(|i| {
            let output = &outputs[i];
            *offset += output.amount.consensus_encode(&mut buffer).unwrap();
            if let Some(script) = output.script {
                *offset += consensus_encode_with_size(script, &mut buffer).unwrap()
            }
        });
        *offset += lock_time.consensus_encode(&mut buffer).unwrap();
        if subscript_index != u64::MAX {
            *offset += SIGHASH_ALL.consensus_encode(&mut buffer).unwrap();
        }
        buffer
    }
}
impl<'a> TryRead<'a, Endian> for Transaction<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<u16>(offset, endian)?;
        let tx_type_uint = bytes.read_with::<u16>(offset, endian)?;
        let tx_type = TransactionType::from(tx_type_uint);
        let count_var = bytes.read_with::<VarInt>(offset, endian)?;
        let count = count_var.0;
        // at least one input is required
        if count == 0 && tx_type.requires_inputs() {
            return Err(byte::Error::Incomplete);
        }
        let mut inputs: Vec<TransactionInput> = Vec::new();
        for _i in 0..count {
            inputs.push(bytes.read_with::<TransactionInput>(offset, endian)?);
        }
        let mut outputs: Vec<TransactionOutput> = Vec::new();
        let count_var = bytes.read_with::<VarInt>(offset, endian)?;
        let count = count_var.0;
        for _i in 0..count {
            outputs.push(bytes.read_with::<TransactionOutput>(offset, endian)?);
        }
        let lock_time = bytes.read_with::<u32>(offset, endian)?;
        let mut tx = Self {
            inputs,
            outputs,
            tx_hash: None,
            version,
            tx_type,
            lock_time,
            payload_offset: *offset,
            block_height: TX_UNCONFIRMED as u32
        };
        tx.tx_hash = if tx_type == Classic {
            Some(UInt256(sha256d::Hash::hash(&tx.to_data()).into_inner()))
        } else {
            None
        };
        Ok((tx, *offset))
    }
}
