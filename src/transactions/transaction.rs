use byte::{BytesExt, LE};
use hashes::Hash;
use crate::blockdata::opcodes::all::OP_RETURN;
use crate::consensus::{Decodable, Encodable};
use crate::consensus::encode::{consensus_encode_with_size, VarInt};
use crate::crypto::byte_util::{data_at_offset_from, UInt256};
use crate::hashes::{sha256d};
use crate::hashes::_export::_core::fmt::Debug;
use crate::transactions::transaction::TransactionType::Classic;

// estimated size for a typical transaction output
pub static TX_OUTPUT_SIZE: usize = 34;
// estimated size for a typical compact pubkey transaction input
pub static TX_INPUT_SIZE: usize = 148;
// standard tx fee per b of tx size
pub static TX_FEE_PER_B: u64 = 1;
// standard ix fee per input
pub static TX_FEE_PER_INPUT: u64 = 10000;
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

// #[repr(C)]
#[derive(Debug)]
pub struct TransactionInput<'a> {
    pub input_hash: UInt256,
    pub index: u32,
    pub script: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub sequence: u32,
}

// #[repr(C)]
#[derive(Debug)]
pub struct TransactionOutput<'a> {
    pub amount: u64,
    pub script: Option<&'a [u8]>,
    pub address: Option<&'a str>,
}
pub trait ITransaction {
    fn payload_data(&self) -> Vec<u8>;
    fn payload_data_for(&self) -> Vec<u8>;
    fn transaction_type(&self) -> TransactionType;
}

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
    fn payload_data(&self) -> Vec<u8> {
        Vec::new()
    }

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

    pub fn new(message: &'a [u8]) -> Option<Self> {
        let payload_offset = &mut 0;
        let version = match message.read_with::<u16>(payload_offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let tx_type = match message.read_with::<u16>(payload_offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let tx_type = TransactionType::from(tx_type);

        let count_var = match VarInt::consensus_decode(&message[*payload_offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let count = count_var.0;
        *payload_offset += count_var.len();

        if count == 0 && tx_type.requires_inputs() {
            return None; // at least one input is required
        }
        let mut inputs: Vec<TransactionInput> = Vec::new();
        for _i in 0..count {
            let input_hash = match message.read_with::<UInt256>(payload_offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let index = match message.read_with::<u32>(payload_offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let signature: Option<&[u8]> = match data_at_offset_from(message, payload_offset) {
                Ok(data) => Some(data),
                Err(_err) => None
            };
            let sequence = match message.read_with::<u32>(payload_offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let input = TransactionInput {
                input_hash,
                index,
                script: None,
                signature,
                sequence
            };
            inputs.push(input);
        }
        let mut outputs: Vec<TransactionOutput> = Vec::new();

        let count_var = match VarInt::consensus_decode(&message[*payload_offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let count = count_var.0;
        *payload_offset += count_var.len();

        for _i in 0..count {
            let amount = match message.read_with::<u64>(payload_offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let script: Option<&[u8]> = match data_at_offset_from(message, payload_offset) {
                Ok(data) => Some(data),
                Err(_err) => None
            };
            let output = TransactionOutput { amount, script, address: None };
            outputs.push(output);
        }

        let lock_time = match message.read_with::<u32>(payload_offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        //let payload_offset = off;

        let mut tx = Self {
            inputs,
            outputs,
            tx_hash: None,
            version,
            tx_type,
            lock_time,
            payload_offset: payload_offset.clone(),
            block_height: TX_UNCONFIRMED as u32
        };
        tx.tx_hash = if tx_type == Classic {
            Some(UInt256(sha256d::Hash::hash(&tx.to_data()).into_inner()))
        } else {
            None
        };
        Some(tx)
    }

    // used in CreditFundingTransaction only
    /*pub fn accounts(&self) -> Vec<Account> {
        self.chain.accounts_that_can_contain_transaction(Some(self))
    }*/

    // used in UI only
    /*pub fn confirmations(&self) -> u32 {
        if self.block_height != TX_UNCONFIRMED {
            self.chain.last_terminal_block_height - self.block_height
        } else {
            0
        }
    }*/

    // used in CreditFundingTransaction only
    /*pub fn first_account(&self) -> Option<Account> {
        self.chain.first_account_that_can_contain_transaction(Some(self))
    }*/

    // unused at this moment
    /*pub fn input_addresses(&self) -> Vec<&str> {
         self.inputs
             .iter()
             .map(|i| if let Some(script) = i.script {
                 address_with_script_pub_key(&script, self.chain.pub_key_address(), self.chain.script_address())
             } else {
                 address_with_script_signature(*i.signature, self.chain.pub_key_address(), self.chain.script_address())
             })
             .collect()
     }

    pub fn output_addresses(&self) -> Vec<&'a str> {
        self.outputs
            .iter()
            .map(|o| *o.address)
            .collect()
    }*/

    // size in bytes if signed, or estimated size assuming compact pubkey sigs
    pub fn size(&self) -> usize {
        // size in bytes if signed, or estimated size assuming compact pubkey sigs
        if self.tx_hash.is_some() {
            return self.to_data().len();
        }
        let input_count = self.inputs.len();
        let output_count = self.outputs.len();
        8 + VarInt(input_count as u64).len() + VarInt(output_count as u64).len() +
            TX_INPUT_SIZE + input_count + TX_OUTPUT_SIZE + output_count
    }

    pub fn standard_fee(&self) -> u64 {
        self.size() as u64 * TX_FEE_PER_B as u64
    }

    pub fn standard_instant_fee(&self) -> u64 {
        TX_FEE_PER_INPUT * self.inputs.len() as u64
    }



    // checks if all signatures exist, but does not verify them
    pub fn is_signed(&self) -> bool {
        let mut signed = true;
        for input in &self.inputs {
            let input_is_signed = input.signature.is_some();
            signed &= input_is_signed;
            if !input_is_signed {
                break;
            }
        }
        return signed;
    }

    pub fn is_coinbase_classic_transaction(&self) -> bool {
        self.inputs.len() == 1 &&
            self.inputs[0].input_hash.0.is_empty() &&
            self.inputs[0].index == u32::MAX
    }

    pub fn is_credit_funding_transaction(&self) -> bool {
        for output in &self.outputs {
            if let Some(script) = output.script {
                let code = match script.read_with::<u8>(&mut 0, LE) {
                    Ok(data) => data,
                    Err(_err) => { continue; }
                };
                if code == OP_RETURN.into_u8() &&
                    script.len() == 22 {
                    return true;
                }
            }
        }
        false
    }


}
