use thiserror::Error;

mod v2;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    IOError(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid value")]
    InvalidValue,
    #[error("Custom error: {0}")]
    Custom(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub use sia_derive::{AsyncSiaDecode, AsyncSiaEncode};
pub use v2::{AsyncDecoder, AsyncEncoder, AsyncSiaDecodable, AsyncSiaEncodable};
