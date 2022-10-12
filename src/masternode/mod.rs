use byte::{BytesExt, LE};
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use dash_spv_primitives::impl_bytes_decodable;

pub mod llmq_entry;
pub mod masternode_entry;
pub mod masternode_list;

pub use self::llmq_entry::LLMQEntry;
pub use self::masternode_entry::MasternodeEntry;
pub use self::masternode_list::MasternodeList;

impl_bytes_decodable!(MasternodeEntry);
impl_bytes_decodable!(LLMQEntry);
