#[warn(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub enum ProcessingError {
    None = 0,
    Skipped = 1,
    ParseError = 2,
    HasNoBaseBlockHash = 3,
}

impl From<u8> for ProcessingError {
    fn from(orig: u8) -> Self {
        match orig {
            0 => ProcessingError::None,
            1 => ProcessingError::ParseError,
            2 => ProcessingError::HasNoBaseBlockHash,
            3 => ProcessingError::Skipped,
            _ => ProcessingError::None,
        }
    }
}

impl Into<u8> for ProcessingError {
    fn into(self) -> u8 {
        match self {
            ProcessingError::None => 0,
            ProcessingError::Skipped => 1,
            ProcessingError::ParseError => 2,
            ProcessingError::HasNoBaseBlockHash => 3,
        }
    }
}

