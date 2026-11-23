use std::io;

use thiserror::Error;

use crate::rhp4::SECTOR_SIZE;

mod v1;
mod v2;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid length")]
    InvalidLength(usize),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
    #[error("Custom error: {0}")]
    Custom(String),
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            Self::Io(e) => Self::Io(io::Error::new(e.kind(), e.to_string())),
            Self::InvalidLength(n) => Self::InvalidLength(*n),
            Self::InvalidValue(s) => Self::InvalidValue(s.clone()),
            Self::Custom(s) => Self::Custom(s.clone()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The most a decoded length prefix may allocate before its bytes arrive.
/// Lengths come from the peer, so longer values grow as data is read. One
/// sector, so a sector read still allocates once.
pub(crate) const MAX_PREALLOC: usize = SECTOR_SIZE;

pub use sia_core_derive::{SiaDecode, SiaEncode};
pub use v2::{SiaDecodable, SiaEncodable};

pub use sia_core_derive::{V1SiaDecode, V1SiaEncode};
pub use v1::{V1SiaDecodable, V1SiaEncodable};
