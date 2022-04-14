use byte::{BytesExt, LE};
use dash_spv_primitives::{impl_bytes_decodable};
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use crate::ffi::types::LLMQSnapshot;

impl_bytes_decodable!(LLMQSnapshot);
