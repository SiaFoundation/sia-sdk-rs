use crate::encoding::Error;

mod v2;

pub use sia_derive::{AsyncSiaDecode, AsyncSiaEncode};
pub use v2::{AsyncDecoder, AsyncEncoder, AsyncSiaDecodable, AsyncSiaEncodable};
