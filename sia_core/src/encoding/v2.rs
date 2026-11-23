use chrono::{DateTime, Duration, Utc};

use super::{Error, MAX_PREALLOC, Result};
use std::io::{Read, Write};

pub trait SiaEncodable {
    fn encoded_length(&self) -> usize;
    fn encode<W: Write>(&self, w: &mut W) -> Result<()>;
}

pub trait SiaDecodable: Sized {
    fn decode<R: Read>(r: &mut R) -> Result<Self>;
}

impl SiaEncodable for u8 {
    fn encoded_length(&self) -> usize {
        1
    }

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
    fn encoded_length(&self) -> usize {
        1
    }

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
            _ => Err(Error::InvalidValue("requires 0 or 1".into())),
        }
    }
}

impl SiaEncodable for DateTime<Utc> {
    fn encoded_length(&self) -> usize {
        8
    }

    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.timestamp().encode(w)
    }
}

impl SiaDecodable for DateTime<Utc> {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let timestamp = i64::decode(r)?;
        DateTime::from_timestamp_secs(timestamp)
            .ok_or_else(|| Error::InvalidValue(format!("invalid timestamp: {timestamp}")))
    }
}

impl SiaEncodable for Duration {
    fn encoded_length(&self) -> usize {
        8
    }

    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.num_nanoseconds()
            .ok_or_else(|| Error::InvalidValue("duration too large".into()))?
            .encode(w)
    }
}

impl SiaDecodable for Duration {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        Ok(Duration::nanoseconds(i64::decode(r)?))
    }
}

impl<T: SiaEncodable> SiaEncodable for [T] {
    fn encoded_length(&self) -> usize {
        let mut len = 0;
        len += self.len().encoded_length();
        for item in self {
            len += item.encoded_length();
        }
        len
    }

    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.len().encode(w)?;
        for item in self {
            item.encode(w)?;
        }
        Ok(())
    }
}

impl<T: SiaEncodable> SiaEncodable for Option<T> {
    fn encoded_length(&self) -> usize {
        1 + match self {
            Some(v) => v.encoded_length(),
            None => 0,
        }
    }
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
        match bool::decode(r)? {
            true => Ok(Some(T::decode(r)?)),
            false => Ok(None),
        }
    }
}

macro_rules! impl_sia_numeric {
    ($($t:ty),*) => {
        $(
            impl SiaEncodable for $t {
                fn encoded_length(&self) -> usize {
                    8
                }

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
    fn encoded_length(&self) -> usize {
        let mut len = 0;
        len += self.len().encoded_length();
        for item in self {
            len += item.encoded_length();
        }
        len
    }
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
        let mut vec = Vec::new();
        // note: the vec is not pre-allocated
        // to prevent abuse by sending a large len
        for _ in 0..usize::decode(r)? {
            vec.push(T::decode(r)?);
        }
        Ok(vec)
    }
}

impl SiaEncodable for String {
    fn encoded_length(&self) -> usize {
        self.as_bytes().encoded_length()
    }

    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        self.as_bytes().encode(w)
    }
}

impl SiaDecodable for String {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let buf = Vec::<u8>::decode(r)?;
        String::from_utf8(buf).map_err(|e| Error::InvalidValue(e.to_string()))
    }
}

impl SiaEncodable for bytes::Bytes {
    fn encoded_length(&self) -> usize {
        8 + self.len()
    }

    fn encode<W: Write>(&self, w: &mut W) -> Result<()> {
        (self.len() as u64).encode(w)?;
        w.write_all(self)?;
        Ok(())
    }
}

impl SiaDecodable for bytes::Bytes {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut remaining = u64::decode(r)?;
        // The first chunk is allocated zeroed, which calloc does without a fill.
        let first = remaining.min(MAX_PREALLOC as u64) as usize;
        let mut buf = vec![0u8; first];
        r.read_exact(&mut buf)?;
        remaining -= first as u64;
        while remaining > 0 {
            let n = remaining.min(MAX_PREALLOC as u64) as usize;
            let start = buf.len();
            buf.resize(start + n, 0);
            r.read_exact(&mut buf[start..])?;
            remaining -= n as u64;
        }
        Ok(bytes::Bytes::from(buf))
    }
}

impl<const N: usize> SiaEncodable for [u8; N] {
    fn encoded_length(&self) -> usize {
        N
    }
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

    #[test]
    fn bytes_length_is_not_allocated_up_front() {
        // The peer claims 2^62 bytes and sends ten.
        let mut wire = (1u64 << 62).to_le_bytes().to_vec();
        wire.extend_from_slice(&[7; 10]);
        let err = bytes::Bytes::decode(&mut &wire[..]).unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
            "{err:?}"
        );
    }

    #[test]
    fn bytes_longer_than_one_allocation() {
        let value = bytes::Bytes::from(vec![9u8; MAX_PREALLOC * 2 + 5]);
        let mut wire = Vec::new();
        value.encode(&mut wire).unwrap();
        assert_eq!(bytes::Bytes::decode(&mut &wire[..]).unwrap(), value);
    }
}
