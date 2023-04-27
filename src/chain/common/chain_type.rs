use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use hashes::hex::FromHex;
use crate::chain::{BIP32ScriptMap, DIP14ScriptMap, ScriptMap, SporkParams};
use crate::chain::params::DUFFS;
use crate::common::LLMQType;
use crate::crypto::{byte_util::Reversable, UInt256};

pub trait IHaveChainSettings {
    fn genesis_hash(&self) -> UInt256;
    fn genesis_height(&self) -> u32;
    fn is_llmq_type(&self) -> LLMQType;
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool;
    fn is_evolution_enabled(&self) -> bool;
}

#[repr(C)]
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
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum DevnetType {
    JackDaniels = 0,
    Devnet333 = 1,
    Chacha = 2,
    #[default]
    Mojito = 3,
    WhiteRussian = 4,
    MiningTest = 5,
    Mobile2 = 6,
    Zero = 7,
}

impl From<DevnetType> for ChainType {
    fn from(orig: DevnetType) -> Self {
        ChainType::DevNet(orig)
    }
}

impl From<ChainType> for DevnetType {
    fn from(orig: ChainType) -> Self {
        match orig {
            ChainType::DevNet(devnet_type) => devnet_type,
            _ => panic!("Can't get DevnetType from ChainType {:?}", orig)
        }
    }
}

impl From<i16> for DevnetType {
    fn from(orig: i16) -> Self {
        match orig {
            0 => DevnetType::JackDaniels,
            1 => DevnetType::Devnet333,
            2 => DevnetType::Chacha,
            3 => DevnetType::Mojito,
            4 => DevnetType::WhiteRussian,
            5 => DevnetType::MiningTest,
            6 => DevnetType::Mobile2,
            7 => DevnetType::Zero,
            _ => DevnetType::JackDaniels,
        }
    }
}

impl From<DevnetType> for i16 {
    fn from(value: DevnetType) -> Self {
        match value {
            DevnetType::JackDaniels => 0,
            DevnetType::Devnet333 => 1,
            DevnetType::Chacha => 2,
            DevnetType::Mojito => 3,
            DevnetType::WhiteRussian => 4,
            DevnetType::MiningTest => 5,
            DevnetType::Mobile2 => 6,
            DevnetType::Zero => 7,
        }
    }
}

impl From<&str> for DevnetType {
    fn from(value: &str) -> Self {
        match value {
            "jack-daniels" => DevnetType::JackDaniels,
            "333" => DevnetType::Devnet333,
            "chacha" => DevnetType::Chacha,
            "mojito" => DevnetType::Mojito,
            "white-russian" => DevnetType::WhiteRussian,
            "miningTest" => DevnetType::MiningTest,
            "devnet-mobile-2" => DevnetType::Mobile2,
            "0" => DevnetType::Zero,
            _ => panic!("Devnet with name: {} not supported", value)
        }
    }
}


impl DevnetType {
    pub fn identifier(&self) -> String {
        match self {
            DevnetType::JackDaniels => "jack-daniels".to_string(),
            DevnetType::Devnet333 => "333".to_string(),
            DevnetType::Chacha => "chacha".to_string(),
            DevnetType::Mojito => "mojito".to_string(),
            DevnetType::WhiteRussian => "white-russian".to_string(),
            DevnetType::MiningTest => "miningTest".to_string(),
            DevnetType::Mobile2 => "devnet-mobile-2".to_string(),
            DevnetType::Zero => "0".to_string(),
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

    pub fn is_testnet(&self) -> bool {
        *self == ChainType::TestNet
    }

    pub fn is_devnet_any(&self) -> bool {
        !self.is_mainnet() && !self.is_testnet()
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
            ChainType::MainNet => UInt256::from_hex("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6").unwrap().reverse(),
            ChainType::TestNet => UInt256::from_hex("00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c").unwrap().reverse(),
            ChainType::DevNet(devnet_type) => devnet_type.genesis_hash(),
        }
    }

    fn genesis_height(&self) -> u32 {
        self.is_devnet_any().into()
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
            ChainType::TestNet => LLMQType::Llmqtype25_67,
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
            DevnetType::JackDaniels => "79ee40288949fd61132c025761d4f065e161d60a88aab4c03e613ca8718d1d26",
            DevnetType::Chacha => "8862eca4bdb5255b51dc72903b8a842f6ffe7356bc40c7b7a7437b8e4556e220",
            DevnetType::Mojito => "739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357",
            DevnetType::WhiteRussian => "9163d6958065ca5e73c36f0f2474ce618846260c215f5cba633bd0003585cb35",
            _ => "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
        }).unwrap().reverse()
    }

    fn genesis_height(&self) -> u32 {
        1
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
        LLMQType::LlmqtypeTestnetPlatform
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
// Params
impl ChainType {
    pub fn magic(&self) -> u32 {
        match self {
            ChainType::MainNet => 0xbd6b0cbf,
            ChainType::TestNet => 0xffcae2ce,
            ChainType::DevNet(_) => 0xceffcae2,
        }
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        !self.is_mainnet()
    }

    pub fn max_proof_of_work(&self) -> UInt256 {
        if self.is_devnet_any() {
            UInt256::from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()
        } else {
            UInt256::from_hex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap()
        }.reverse()
    }

    pub fn max_proof_of_work_target(&self) -> u32 {
        if self.is_devnet_any() { 0x207fffff } else { 0x1e0fffff }
    }

    pub fn min_protocol_version(&self) -> u32 {
        match self {
            ChainType::MainNet => 70218,
            ChainType::TestNet => 70218,
            ChainType::DevNet(_) => 70219
        }
    }

    pub fn protocol_version(&self) -> u32 {
        match self {
            ChainType::MainNet => 70219,
            ChainType::TestNet => 70227,
            ChainType::DevNet(_) => 70227
        }
    }

    pub fn standard_port(&self) -> u16 {
        match self {
            ChainType::MainNet => 9999,
            ChainType::TestNet => 19999,
            ChainType::DevNet(_) => 20001
        }
    }

    pub fn standard_dapi_grpc_port(&self) -> u16 { 3010 }

    pub fn standard_dapi_jrpc_port(&self) -> u16 { 3000 }

    pub fn localhost(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0x7f000001), self.standard_port()))
    }

    pub fn transaction_version(&self) -> u16 {
        match self {
            ChainType::MainNet => 1,
            ChainType::TestNet => 1,
            _ => 3,
        }
    }

    pub fn base_reward(&self) -> u64 {
        match self {
            ChainType::MainNet => 5 * DUFFS,
            _ => 50 * DUFFS
        }
    }

    pub fn header_max_amount(&self) -> u64 {
        2000
    }

    pub fn spork_params(&self) -> SporkParams {
        match self {
            ChainType::MainNet => SporkParams {
                public_key_hex_string: Some("04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd".to_string()),
                private_key_base58_string: None,
                address: "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh".to_string()
            },
            ChainType::TestNet => SporkParams {
                public_key_hex_string: Some("046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e".to_string()),
                private_key_base58_string: None,
                address: "yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55".to_string()
            },
            ChainType::DevNet(devnet) => SporkParams {
                public_key_hex_string: None,
                private_key_base58_string: match devnet {
                    DevnetType::Chacha => Some("cPTms6Sd7QuhPWXWQSzMbvg2VbEPsWCsLBbR4PBgvfYRzAPazbt3".to_string()),
                    DevnetType::Devnet333 => Some("cQnP9JNQp6oaZrvBtqBWRMeQERMkDyuXyvQh1qaph4FdP6cT2cVa".to_string()),
                    DevnetType::JackDaniels => Some("cTeGz53m7kHgA9L75s4vqFGR89FjYz4D9o44eHfoKjJr2ArbEtwg".to_string()),
                    _ => Some("".to_string())
                },
                address: match devnet {
                    DevnetType::Chacha => "ybiRzdGWFeijAgR7a8TJafeNi6Yk6h68ps".to_string(),
                    DevnetType::Devnet333 => "yM6zJAMWoouAZxPvqGDbuHb6BJaD6k4raQ".to_string(),
                    DevnetType::JackDaniels => "yYBanbwp2Pp2kYWqDkjvckY3MosuZzkKp7".to_string(),
                    _ => "".to_string(),
                }
            }
        }
    }

    pub fn use_legacy_bls(&self) -> bool {
        !self.is_mainnet()
    }

    pub fn peer_misbehaving_threshold(&self) -> usize {
        match self {
            ChainType::MainNet => 20,
            ChainType::TestNet => 40,
            ChainType::DevNet(_) => 4
        }
    }

}
