use std::io;

use thiserror::Error;

mod v1;
mod v2;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Invalid length")]
    InvalidLength(usize),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
    #[error("Custom error: {0}")]
    Custom(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub use sia_derive::{SiaDecode, SiaEncode};
pub use v2::{SiaDecodable, SiaEncodable};

pub use sia_derive::{V1SiaDecode, V1SiaEncode};
pub use v1::{V1SiaDecodable, V1SiaEncodable};
