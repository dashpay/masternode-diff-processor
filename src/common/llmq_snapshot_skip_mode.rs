use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum LLMQSnapshotSkipMode {
    // No skipping. The skip list is empty.
    NoSkipping = 0,
    // Skip the first entry of the list.
    // The following entries contain the relative position of subsequent skips.
    // For example, if during the initialization phase you skip entries x, y and z of the models
    // list, the skip list will contain x, y-x and z-y in this mode.
    SkipFirst = 1,
    // Contains the entries which were not skipped.
    // This is better when there are many skips.
    // Mode 2 is more efficient and should be used when 3/4*quorumSize ≥ 1/2*masternodeNb or
    // quorumsize ≥ 2/3*masternodeNb
    SkipExcept = 2,
    // Every node was skipped. The skip list is empty. DKG sessions were not attempted.
    SkipAll = 3,
}
impl From<u32> for LLMQSnapshotSkipMode {
    fn from(orig: u32) -> Self {
        match orig {
            0 => LLMQSnapshotSkipMode::NoSkipping,
            1 => LLMQSnapshotSkipMode::SkipFirst,
            2 => LLMQSnapshotSkipMode::SkipExcept,
            3 => LLMQSnapshotSkipMode::SkipAll,
            _ => LLMQSnapshotSkipMode::NoSkipping,
        }
    }
}

impl<'a> TryRead<'a, Endian> for LLMQSnapshotSkipMode {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        Ok((
            LLMQSnapshotSkipMode::from(bytes.read_with::<u32>(&mut 0, LE)?),
            4,
        ))
    }
}
