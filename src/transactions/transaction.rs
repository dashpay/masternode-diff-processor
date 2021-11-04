use std::collections::HashSet;
use std::convert::TryFrom;
use std::io::BufWriter;
use std::time::Instant;
use byte::{BytesExt, LE, TryWrite};
use crate::blockdata::opcodes::all::OP_RETURN;
use crate::consensus::encode::VarInt;
use crate::crypto::{DASH_PUBKEY_ADDRESS, DASH_PUBKEY_ADDRESS_TEST};
use crate::crypto::data_ops::{address_with_script_pub_key, address_with_script_signature, sha256_2};
use crate::transactions::instant_send_transaction_lock::InstantSendTransactionLock;
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


#[repr(C)]
#[derive(Copy, Clone, Debug)]
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

impl TransactionType {
    fn raw_value(&self) -> u16 {
        *self as u16
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TransactionInput {
    pub input_hash: [u8; 32],
    pub index: u32,
    pub script: Option<[u8]>,
    pub signature: Option<[u8]>,
    pub sequence: u32,
}
#[repr(C)]
#[derive(Debug)]
pub struct TransactionOutput<'a> {
    pub amount: u64,
    pub script: Option<[u8]>,
    pub address: Option<&'a str>,
}
pub trait ITransaction {
    fn payload_data(&self) -> &[u8];
    fn payload_data_for(&self) -> &[u8];
}

pub struct Transaction<'a, T: ITransaction> {

    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput<'a>>,

    pub lock_time: u32,
    pub version: u16,
    pub tx_hash: Option<[u8; 32]>,
    pub tx_type: TransactionType,

    pub payload_offset: &'a mut usize,
    pub block_height: u32,
}

impl<'a> Transaction<dyn ITransaction> {
    fn payload_data(&self) -> &[u8] {
        [] as &[u8]
    }

    fn transaction_type_requires_inputs() -> bool {
        return true;
    }
    fn to_data(&self) -> &[u8] {
        self.to_data_with_subscript_index(u64::MAX)
    }

    fn to_data_with_subscript_index(&self, subscript_index: u64) -> &[u8] {
        let mut buffer = [0u8; 12];
        let offset: &mut usize = &mut 0;
        buffer.write(offset, self.version);
        buffer.write(offset, self.tx_type.raw_value());
        let inputs_len = self.inputs.len();
        buffer.write(offset, VarInt(inputs_len as u64));
        for i in 0..inputs_len {
            let input = self.inputs.get(i)?;
            buffer.write(offset, input.input_hash);
            buffer.write(offset, input.index);
            if subscript_index == u64::MAX && input.signature != None {
                let signature = input.signature?;
                buffer.write(offset, signature?.len());
                buffer.write(offset, signature);
            } else if subscript_index == i && input.script != None {
                let script = input.script?;
                buffer.write(offset, VarInt(script.len() as u64));
                buffer.write(offset, script);
            } else {
                buffer.write(offset, VarInt(0 as u64));
            }
            buffer.write(offset, input.sequence);
        }
        let outputs_len = self.outputs.len();
        buffer.write(offset, VarInt(outputs_len as u64));
        for i in 0..outputs_len {
            let output = self.outputs.get(i)?;
            buffer.write(offset, output.amount);
            if output.script != None {
                let script = output.script?;
                buffer.write(offset, script.len());
                buffer.write(offset, script);
            }
        }
        buffer.write(offset, self.lock_time);
        if subscript_index != u64::MAX {
            buffer.write(offset, 0x00000001 as u32);
        }
        &buffer
    }
}
impl<'a> Transaction<dyn ITransaction> {
    pub fn new(message: &[u8]) -> Option<Self> {
        let off = &mut 0;
        let version = message.read_with::<u16>(off, LE)?;
        let tx_type = message.read_with::<u16>(off, LE)?;
        let count = VarInt(off as u64);
        if count == 0 && self::transaction_type_requires_inputs() {
            return None; // at least one input is required
        }
        let mut inputs: Vec<TransactionInput> = Vec::new();
        for _i in 0..count {
            let input_hash = message.read_with::<[u8; 32]>(off, LE)?;
            let index = message.read_with::<u32>(off, LE)?;
            let signature = message.read_with::<[u8]>(off, LE)?;
            let sequence = message.read_with::<u32>(off, LE)?;
            let input = TransactionInput {
                input_hash,
                index,
                script: None,
                signature: Some(signature),
                sequence
            };
            inputs.push(input);
        }
        let mut outputs: Vec<TransactionOutput> = Vec::new();
        let count = VarInt(off as u64);
        for _i in 0..count {
            let amount = message.read_with::<u64>(off, LE)?;
            let script = message.read_with::<[u8]>(off, LE)?;
            let output = TransactionOutput {
                amount,
                script: Some(script),
                address: None
            };
            outputs.push(output);
        }

        let lock_time = message.read_with::<u32>(off, LE)?;
        let payload_offset = off;
        let tx_hash: Option<[u8; 32]> =
            if tx_type == Classic.raw_value() {
                Some(sha256_2(&base.data))
            } else {
                None
             };

        Some(Self {
            inputs,
            outputs,
            tx_hash,
            version,
            tx_type: TransactionType::try_from(tx_type)?,
            lock_time,
            payload_offset,
            block_height: TX_UNCONFIRMED as u32
        })
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
        (self.size() * TX_FEE_PER_B) as u64
    }

    pub fn standard_instant_fee(&self) -> u64 {
        TX_FEE_PER_INPUT * self.inputs.len()
    }



    // checks if all signatures exist, but does not verify them
    pub fn is_signed(&self) -> bool {
        let mut signed = true;
        for input in self.inputs {
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
            self.inputs[0].input_hash.is_empty() &&
            self.inputs[0].index == u32::MAX
    }

    pub fn is_credit_funding_transaction(&self) -> bool {
        for output in self.outputs {
            if let Some(script) = output.script {
                if script[0..7] == OP_RETURN &&
                    script.len() == 22 {
                    return true;
                }
            }
        }
        false
    }


}
