use serde::{Deserialize, Serialize};
use uint::construct_uint;

use crate::encoding::{self, SiaDecodable, SiaEncodable, V1SiaDecodable, V1SiaEncodable};

construct_uint! {
    /// Work is a 256-bit unsigned integer.
    pub struct Work(4);
}

impl From<&[u8; 32]> for Work {
    fn from(bytes: &[u8; 32]) -> Self {
        Work::from_big_endian(bytes)
    }
}

impl SiaEncodable for Work {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.to_big_endian().encode(w)
    }
}

impl SiaDecodable for Work {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        Ok(Work::from_big_endian(&<[u8; 32]>::decode(r).map_err(
            |_| encoding::Error::Custom("invalid work".to_string()),
        )?))
    }
}

impl V1SiaEncodable for Work {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.to_big_endian().encode_v1(w)
    }
}

impl V1SiaDecodable for Work {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        Ok(Work::from_big_endian(&<[u8; 32]>::decode_v1(r)?))
    }
}

impl Serialize for Work {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Work {
    fn deserialize<D>(deserializer: D) -> Result<Work, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Work::from_dec_str(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
