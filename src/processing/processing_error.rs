#[warn(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub enum ProcessingError {
    Skipped = 0,
    ParseError = 1,
    HasNoBaseBlockHash = 2,
}

impl From<u8> for ProcessingError {
    fn from(orig: u8) -> Self {
        match orig {
            0 => ProcessingError::Skipped,
            1 => ProcessingError::ParseError,
            2 => ProcessingError::HasNoBaseBlockHash,
            _ => ProcessingError::Skipped,
        }
    }
}

impl Into<u8> for ProcessingError {
    fn into(self) -> u8 {
        match self {
            ProcessingError::Skipped => 0,
            ProcessingError::ParseError => 1,
            ProcessingError::HasNoBaseBlockHash => 2,
        }
    }
}

