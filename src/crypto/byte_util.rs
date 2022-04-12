use byte::{BytesExt, LE};
use dash_spv_primitives::{impl_bytes_decodable, impl_bytes_decodable_lt};
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use crate::{CoinbaseTransaction, MasternodeEntry, LLMQEntry};
use crate::ffi::types::LLMQSnapshot;
use crate::transactions::transaction::{Transaction, TransactionInput, TransactionOutput};

impl_bytes_decodable!(MasternodeEntry);
impl_bytes_decodable!(LLMQSnapshot);

impl_bytes_decodable_lt!(TransactionInput);
impl_bytes_decodable_lt!(TransactionOutput);
impl_bytes_decodable_lt!(Transaction);
impl_bytes_decodable_lt!(CoinbaseTransaction);
impl_bytes_decodable_lt!(LLMQEntry);
