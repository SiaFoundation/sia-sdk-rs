use crate::encoding::Error;

mod v2;

pub type Result<T> = std::result::Result<T, Error>;

pub use sia_derive::{AsyncSiaDecode, AsyncSiaEncode};
pub use v2::{AsyncDecoder, AsyncEncoder, AsyncSiaDecodable, AsyncSiaEncodable};
