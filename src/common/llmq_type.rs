
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum LLMQType {
    LLMQType_50_60 = 1,  // every 24 blocks
    LLMQType_400_60 = 2, // 288 blocks
    LLMQType_400_85 = 3, // 576 blocks
    LLMQType_100_67 = 4, // every 24 blocks
    LLMQType_5_60 = 100, // 24 blocks
    LLMQType_10_60 = 101, // 24 blocks
}
