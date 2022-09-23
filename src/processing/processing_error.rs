#[warn(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub enum ProcessingError {
    None = 0,
    PersistInRetrieval = 1,
    LocallyStored = 2,
    ParseError = 3,
    HasNoBaseBlockHash = 4,
}

impl From<u8> for ProcessingError {
    fn from(orig: u8) -> Self {
        match orig {
            0 => ProcessingError::None,
            1 => ProcessingError::PersistInRetrieval,
            2 => ProcessingError::LocallyStored,
            3 => ProcessingError::ParseError,
            4 => ProcessingError::HasNoBaseBlockHash,
            _ => ProcessingError::None,
        }
    }
}

impl Into<u8> for ProcessingError {
    fn into(self) -> u8 {
        match self {
            ProcessingError::None => 0,
            ProcessingError::PersistInRetrieval => 1,
            ProcessingError::LocallyStored => 2,
            ProcessingError::ParseError => 3,
            ProcessingError::HasNoBaseBlockHash => 4,
        }
    }
}
