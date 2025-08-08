use super::{Error, Result};
use std::io::{Read, Write};
use time::{Duration, OffsetDateTime};

pub trait SiaEncodable {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()>;
}

pub trait SiaDecodable: Sized {
    fn decode<R: Read>(r: &mut R) -> Result<Self>;
}

impl SiaEncodable for u8 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(&[*self])?;
        Ok(())
    }
}

impl SiaDecodable for u8 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0; 1];
        r.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl SiaEncodable for bool {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        (*self as u8).encode(w)
    }
}

impl SiaDecodable for bool {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let v = u8::decode(r)?;
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidValue),
        }
    }
}

impl SiaEncodable for OffsetDateTime {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.unix_timestamp().encode(w)
    }
}

impl SiaDecodable for OffsetDateTime {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let timestamp = i64::decode(r)?;
        Ok(OffsetDateTime::from_unix_timestamp(timestamp).unwrap())
    }
}

impl SiaEncodable for Duration {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        (self.whole_nanoseconds() as u64).encode(w)
    }
}

impl SiaDecodable for Duration {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let ns = u64::decode(r)?;
        if ns > i64::MAX as u64 {
            return Err(Error::InvalidValue);
        }
        Ok(Duration::nanoseconds(ns as i64))
    }
}

impl<T: SiaEncodable> SiaEncodable for [T] {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.len().encode(w)?;
        for item in self {
            item.encode(w)?;
        }
        Ok(())
    }
}

impl<T: SiaEncodable> SiaEncodable for Option<T> {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        match self {
            Some(v) => {
                true.encode(w)?;
                v.encode(w)
            }
            None => false.encode(w),
        }
    }
}

impl<T: SiaDecodable> SiaDecodable for Option<T> {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let has_value = bool::decode(r)?;
        if has_value {
            Ok(Some(T::decode(r)?))
        } else {
            Ok(None)
        }
    }
}

macro_rules! impl_sia_numeric {
    ($($t:ty),*) => {
        $(
            impl SiaEncodable for $t {
                fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
                    w.write_all(&(*self as u64).to_le_bytes())?;
                    Ok(())
                }
            }

            impl SiaDecodable for $t {
                fn decode<R: Read>(r: &mut R) -> Result<Self> {
                    let mut buf = [0u8; 8];
                    r.read_exact(&mut buf)?;
                    Ok(u64::from_le_bytes(buf) as Self)
                }
            }
        )*
    }
}

impl_sia_numeric!(u16, u32, usize, i16, i32, i64, u64);

impl<T> SiaEncodable for Vec<T>
where
    T: SiaEncodable,
{
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.len().encode(w)?;
        for item in self {
            item.encode(w)?;
        }
        Ok(())
    }
}

impl<T> SiaDecodable for Vec<T>
where
    T: SiaDecodable,
{
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let len = usize::decode(r)?;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(r)?);
        }
        Ok(vec)
    }
}

impl SiaEncodable for String {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.as_bytes().encode(w)
    }
}

impl SiaDecodable for String {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let buf = Vec::<u8>::decode(r)?;
        String::from_utf8(buf).map_err(|_| Error::InvalidLength)
    }
}

impl<const N: usize> SiaEncodable for [u8; N] {
    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(self)?;
        Ok(())
    }
}

impl<const N: usize> SiaDecodable for [u8; N] {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut arr = [0u8; N];
        r.read_exact(&mut arr)?;
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_roundtrip<T: SiaEncodable + SiaDecodable + std::fmt::Debug + PartialEq>(
        value: T,
        expected_bytes: Vec<u8>,
    ) {
        let mut encoded_bytes = Vec::new();
        value
            .encode(&mut encoded_bytes)
            .unwrap_or_else(|e| panic!("failed to encode: {e:?}"));

        assert_eq!(
            encoded_bytes, expected_bytes,
            "encoding mismatch for {value:?}"
        );

        let mut bytes = &expected_bytes[..];
        let decoded = T::decode(&mut bytes).unwrap_or_else(|e| panic!("failed to decode: {e:?}"));
        assert_eq!(decoded, value, "decoding mismatch for {value:?}");

        assert_eq!(bytes.len(), 0, "leftover bytes for {value:?}");
    }

    #[test]
    fn test_numerics() {
        test_roundtrip(1u8, vec![1]);
        test_roundtrip(2u16, vec![2, 0, 0, 0, 0, 0, 0, 0]);
        test_roundtrip(3u32, vec![3, 0, 0, 0, 0, 0, 0, 0]);
        test_roundtrip(4u64, vec![4, 0, 0, 0, 0, 0, 0, 0]);
        test_roundtrip(5usize, vec![5, 0, 0, 0, 0, 0, 0, 0]);
        test_roundtrip(-1i16, vec![255, 255, 255, 255, 255, 255, 255, 255]);
        test_roundtrip(-2i32, vec![254, 255, 255, 255, 255, 255, 255, 255]);
        test_roundtrip(-3i64, vec![253, 255, 255, 255, 255, 255, 255, 255]);
    }

    #[test]
    fn test_strings() {
        test_roundtrip(
            "hello".to_string(),
            vec![
                5, 0, 0, 0, 0, 0, 0, 0, // length prefix
                104, 101, 108, 108, 111, // "hello"
            ],
        );
        test_roundtrip(
            "".to_string(),
            vec![0, 0, 0, 0, 0, 0, 0, 0], // empty string length
        );
    }

    #[test]
    fn test_fixed_arrays() {
        test_roundtrip([1u8, 2u8, 3u8], vec![1, 2, 3]);
        test_roundtrip([0u8; 4], vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_vectors() {
        test_roundtrip(
            vec![1u8, 2u8, 3u8],
            vec![
                3, 0, 0, 0, 0, 0, 0, 0, // length prefix
                1, 2, 3, // values
            ],
        );
        test_roundtrip(
            vec![100u64, 200u64],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // length prefix
                100, 0, 0, 0, 0, 0, 0, 0, // 100u64
                200, 0, 0, 0, 0, 0, 0, 0, // 200u64
            ],
        );
        test_roundtrip(
            vec!["a".to_string(), "bc".to_string()],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // vector length
                1, 0, 0, 0, 0, 0, 0, 0,  // first string length
                97, // "a"
                2, 0, 0, 0, 0, 0, 0, 0, // second string length
                98, 99, // "bc"
            ],
        );
    }

    #[test]
    fn test_nested() {
        test_roundtrip(
            vec![vec![1u8, 2u8], vec![3u8, 4u8]],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // outer vec length
                2, 0, 0, 0, 0, 0, 0, 0, // first inner vec length
                1, 2, // first inner vec contents
                2, 0, 0, 0, 0, 0, 0, 0, // second inner vec length
                3, 4, // second inner vec contents
            ],
        );
    }
}
