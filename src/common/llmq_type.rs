use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum LLMQType {
    Llmqtype5060 = 1,  // every 24 blocks
    Llmqtype40060 = 2, // 288 blocks
    Llmqtype40085 = 3, // 576 blocks
    Llmqtype10067 = 4, // every 24 blocks
    Llmqtype560 = 100, // 24 blocks
    Llmqtype1060 = 101, // 24 blocks
}

impl LLMQType {
    pub fn quorum_size(&self) -> u32 {
        match self {
            LLMQType::Llmqtype560 => 5,
            LLMQType::Llmqtype1060 => 10,
            LLMQType::Llmqtype5060 => 50,
            LLMQType::Llmqtype40060 => 400,
            LLMQType::Llmqtype40085 => 400,
            LLMQType::Llmqtype10067 => 100,
        }
    }

    pub fn quorum_threshold(&self) -> u32 {
        match self {
            LLMQType::Llmqtype5060 => 30,
            LLMQType::Llmqtype40060 => 240,
            LLMQType::Llmqtype40085 => 340,
            LLMQType::Llmqtype10067 => 67,
            LLMQType::Llmqtype560 => 3,
            LLMQType::Llmqtype1060 => 6,
        }
    }
}

impl From<u8> for LLMQType {
    fn from(orig: u8) -> Self {
        match orig {
            0x01 => LLMQType::Llmqtype5060,
            0x02 => LLMQType::Llmqtype40060,
            0x03 => LLMQType::Llmqtype40085,
            0x04 => LLMQType::Llmqtype10067,
            0x64 => LLMQType::Llmqtype560,
            0x65 => LLMQType::Llmqtype1060,
            _ => LLMQType::Llmqtype5060
        }
    }
}

impl Into<u8> for LLMQType {
    fn into(self) -> u8 {
        match self {
            LLMQType::Llmqtype5060 => 0x01,
            LLMQType::Llmqtype40060 => 0x02,
            LLMQType::Llmqtype40085 => 0x03,
            LLMQType::Llmqtype10067 => 0x04,
            LLMQType::Llmqtype560 => 0x64,
            LLMQType::Llmqtype1060 => 0x65
        }
    }
}

impl<'a> TryRead<'a, Endian> for LLMQType {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let orig = bytes.read_with::<u8>(offset, endian).unwrap();
        let llmq_type = LLMQType::from(orig);
        Ok((llmq_type, 1))
    }
}

impl<'a> TryWrite<Endian> for LLMQType {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> byte::Result<usize> {
        let orig: u8 = self.into();
        bytes.write_with(&mut 0, orig, endian).unwrap();
        Ok(1)
    }
}
