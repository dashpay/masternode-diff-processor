use hashes::hex::FromHex;
use crate::chain::common::LLMQType;
use crate::chain::{BIP32ScriptMap, DIP14ScriptMap, ScriptMap};
use crate::crypto::byte_util::Reversable;
use crate::crypto::UInt256;

// pub const USER_AGENT: String = format!("/dash-spv-core:{}", env!("CARGO_PKG_VERSION"));

pub trait IHaveChainSettings {
    fn genesis_hash(&self) -> UInt256;
    fn is_llmq_type(&self) -> LLMQType;
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool;
    fn is_evolution_enabled(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum ChainType {
    #[default]
    MainNet,
    TestNet,
    DevNet(DevnetType),
}

impl From<i16> for ChainType {
    fn from(orig: i16) -> Self {
        match orig {
            0 => ChainType::MainNet,
            1 => ChainType::TestNet,
            _ => ChainType::DevNet(DevnetType::default()),
        }
    }
}

impl From<ChainType> for i16 {
    fn from(value: ChainType) -> Self {
        match value {
            ChainType::MainNet => 0,
            ChainType::TestNet => 1,
            ChainType::DevNet(..) => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum DevnetType {
    JackDaniels,
    Devnet333,
    Chacha,
    #[default]
    Mojito,
}

impl DevnetType {
    pub fn identifier(&self) -> String {
        match self {
            DevnetType::JackDaniels => "jack-daniels".to_string(),
            DevnetType::Devnet333 => "333".to_string(),
            DevnetType::Chacha => "chacha".to_string(),
            DevnetType::Mojito => "mojito".to_string(),
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

    pub fn user_agent(&self) -> String {
        format!("/dash-spv-core:{}{}/", env!("CARGO_PKG_VERSION"),
        match self {
            ChainType::MainNet => format!(""),
            ChainType::TestNet => format!("(testnet)"),
            ChainType::DevNet(devnet_type) => format!("(devnet.{})", devnet_type.identifier())
        })
    }

    pub fn coin_type(&self) -> u32 {
        if self.is_mainnet() { 5 } else { 1 }
    }

    pub fn devnet_identifier(&self) -> Option<String> {
        if let ChainType::DevNet(devnet_type) = self {
            Some(devnet_type.identifier())
        } else {
            None
        }
    }

    pub fn devnet_version(&self) -> Option<i16> {
        if let ChainType::DevNet(devnet_type) = self {
            Some(devnet_type.version() as i16)
        } else {
            None
        }
    }

    pub fn dns_seeds(&self) -> Vec<&str> {
        match self {
            ChainType::MainNet => vec!["dnsseed.dash.org"],
            ChainType::TestNet => vec!["testnet-seed.dashdot.io"],
            ChainType::DevNet(_) => vec![]
        }
    }

    pub fn script_map(&self) -> ScriptMap {
        match self {
            ChainType::MainNet => ScriptMap::MAINNET,
            _ => ScriptMap::TESTNET
        }
    }
    pub fn bip32_script_map(&self) -> BIP32ScriptMap {
        match self {
            ChainType::MainNet => BIP32ScriptMap::MAINNET,
            _ => BIP32ScriptMap::TESTNET
        }
    }
    pub fn dip14_script_map(&self) -> DIP14ScriptMap {
        match self {
            ChainType::MainNet => DIP14ScriptMap::MAINNET,
            _ => DIP14ScriptMap::TESTNET
        }
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

    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool {
        self.chain_locks_type() == llmq_type ||
            self.is_llmq_type() == llmq_type ||
            self.platform_type() == llmq_type ||
            self.isd_llmq_type() == llmq_type
    }

    fn is_evolution_enabled(&self) -> bool {
        false
    }
}

impl IHaveChainSettings for DevnetType {

    fn genesis_hash(&self) -> UInt256 {
        UInt256::from_hex(match self {
            DevnetType::Mojito => "739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357",
            _ => "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c"
        }).unwrap().reversed()
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

    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool {
        self.chain_locks_type() == llmq_type ||
            self.is_llmq_type() == llmq_type ||
            self.platform_type() == llmq_type ||
            self.isd_llmq_type() == llmq_type
    }

    fn is_evolution_enabled(&self) -> bool {
        false
    }
}
