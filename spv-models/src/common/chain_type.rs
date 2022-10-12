use dash_spv_primitives::crypto::byte_util::Reversable;
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::hex::FromHex;
use crate::common::LLMQType;

pub trait IHaveChainSettings {
    fn genesis_hash(&self) -> UInt256;
    fn is_llmq_type(&self) -> LLMQType;
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ChainType {
    MainNet,
    TestNet,
    DevNet(DevnetType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DevnetType {
    JackDaniels,
    Devnet333,
}

impl DevnetType {
    pub fn identifier(&self) -> String {
        match self {
            DevnetType::JackDaniels => "jack-daniels".to_string(),
            DevnetType::Devnet333 => "333".to_string(),
        }
    }

    pub fn version(&self) -> u16 {
        1
    }
}

impl ChainType {
    pub fn is_mainnet(&self) -> bool {
        *self == ChainType::MainNet
    }

}

impl IHaveChainSettings for ChainType {

    fn genesis_hash(&self) -> UInt256 {
        match self {
            ChainType::MainNet => UInt256::from_hex("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6").unwrap().reversed(),
            ChainType::TestNet => UInt256::from_hex("00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c").unwrap().reversed(),
            ChainType::DevNet(devnet_type) => devnet_type.genesis_hash(),
        }
    }

    fn is_llmq_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype50_60,
            ChainType::TestNet => LLMQType::Llmqtype50_60,
            ChainType::DevNet(devnet_type) => devnet_type.is_llmq_type(),
        }
    }

    fn isd_llmq_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype60_75,
            ChainType::TestNet => LLMQType::Llmqtype60_75,
            ChainType::DevNet(devnet_type) => devnet_type.isd_llmq_type(),
        }
    }

    fn chain_locks_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype400_60,
            ChainType::TestNet => LLMQType::Llmqtype50_60,
            ChainType::DevNet(devnet_type) => devnet_type.chain_locks_type(),
        }
    }

    fn platform_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype100_67,
            ChainType::TestNet => LLMQType::Llmqtype100_67,
            ChainType::DevNet(devnet_type) => devnet_type.platform_type(),
        }

    }
}

impl IHaveChainSettings for DevnetType {

    fn genesis_hash(&self) -> UInt256 {
        UInt256::from_hex("00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c")
            .unwrap()
            .reversed()
    }

    fn is_llmq_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnetDIP0024
    }

    fn isd_llmq_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnetDIP0024
    }

    fn chain_locks_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnet
    }

    fn platform_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnet
    }
}
