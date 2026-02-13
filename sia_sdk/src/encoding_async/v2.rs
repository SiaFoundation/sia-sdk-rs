use super::Error as EncodingError;
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Duration, Utc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub trait AsyncEncoder {
    type Error: From<EncodingError>;
    fn encode_buf(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
}

pub trait AsyncDecoder {
    type Error: From<EncodingError>;
    fn decode_buf(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<(), Self::Error>>;
}

pub trait AsyncSiaEncodable {
    fn encode_async<E: AsyncEncoder>(
        &self,
        w: &mut E,
    ) -> impl Future<Output = Result<(), E::Error>>;
}

pub trait AsyncSiaDecodable: Sized {
    fn decode_async<D: AsyncDecoder>(r: &mut D) -> impl Future<Output = Result<Self, D::Error>>;
}

impl<T: AsyncWrite + Unpin> AsyncEncoder for T {
    type Error = EncodingError;
    async fn encode_buf(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.write_all(buf).await?;
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncDecoder for T {
    type Error = EncodingError;
    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.read_exact(buf).await?;
        Ok(())
    }
}

impl AsyncSiaEncodable for u8 {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        w.encode_buf(&[*self]).await
    }
}

impl AsyncSiaDecodable for u8 {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let mut buf = [0; 1];
        r.decode_buf(&mut buf).await?;
        Ok(buf[0])
    }
}

impl AsyncSiaEncodable for bool {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        (*self as u8).encode_async(w).await
    }
}

impl AsyncSiaDecodable for bool {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let v = u8::decode_async(r).await?;
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(EncodingError::InvalidValue("requires 0 or 1".into()).into()),
        }
    }
}

impl AsyncSiaEncodable for DateTime<Utc> {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        self.timestamp().encode_async(w).await
    }
}

impl AsyncSiaDecodable for DateTime<Utc> {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let timestamp = i64::decode_async(r).await?;
        Ok(DateTime::from_timestamp_secs(timestamp).ok_or_else(|| {
            EncodingError::InvalidValue(format!("invalid timestamp: {timestamp}"))
        })?)
    }
}

impl AsyncSiaEncodable for Duration {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        self.num_nanoseconds()
            .ok_or_else(|| EncodingError::InvalidValue("duration too large".into()))?
            .encode_async(w)
            .await
    }
}

impl AsyncSiaDecodable for Duration {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let ns = u64::decode_async(r).await?;
        if ns > i64::MAX as u64 {
            return Err(EncodingError::InvalidValue(format!(
                "duration {ns} must be less than {}",
                i64::MAX
            ))
            .into());
        }
        Ok(Duration::nanoseconds(ns as i64))
    }
}

impl AsyncSiaEncodable for Bytes {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        self.len().encode_async(w).await?;
        w.encode_buf(self).await
    }
}

impl AsyncSiaDecodable for Bytes {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let len = usize::decode_async(r).await?;
        let mut buf = BytesMut::zeroed(len);
        r.decode_buf(&mut buf).await?;
        Ok(buf.freeze())
    }
}

impl<T: AsyncSiaEncodable> AsyncSiaEncodable for [T] {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        self.len().encode_async(w).await?;
        for item in self {
            item.encode_async(w).await?;
        }
        Ok(())
    }
}

impl<T: AsyncSiaEncodable> AsyncSiaEncodable for Option<T> {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        match self {
            Some(value) => {
                1u8.encode_async(w).await?;
                value.encode_async(w).await?;
            }
            None => 0u8.encode_async(w).await?,
        }
        Ok(())
    }
}

impl<T: AsyncSiaDecodable> AsyncSiaDecodable for Option<T> {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        match bool::decode_async(r).await? {
            true => Ok(Some(T::decode_async(r).await?)),
            false => Ok(None),
        }
    }
}

impl<T> AsyncSiaEncodable for Vec<T>
where
    T: AsyncSiaEncodable,
{
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        self.len().encode_async(w).await?;
        for item in self {
            item.encode_async(w).await?;
        }
        Ok(())
    }
}

impl<T> AsyncSiaDecodable for Vec<T>
where
    T: AsyncSiaDecodable,
{
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let mut vec = Vec::new();
        // note: the vec is not pre-allocated
        // to prevent abuse by sending a large len
        for _ in 0..usize::decode_async(r).await? {
            vec.push(T::decode_async(r).await?);
        }
        Ok(vec)
    }
}

impl AsyncSiaEncodable for String {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        let bytes = self.as_bytes();
        bytes.encode_async(w).await?;
        Ok(())
    }
}

impl AsyncSiaDecodable for String {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::decode_async(r).await?;
        String::from_utf8(bytes).map_err(|e| EncodingError::InvalidValue(e.to_string()).into())
    }
}

impl<const N: usize> AsyncSiaEncodable for [u8; N] {
    async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
        w.encode_buf(self).await
    }
}

impl<const N: usize> AsyncSiaDecodable for [u8; N] {
    async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
        let mut arr = [0u8; N];
        r.decode_buf(&mut arr).await?;
        Ok(arr)
    }
}

macro_rules! impl_sia_numeric {
    ($($t:ty),*) => {
        $(
            impl AsyncSiaEncodable for $t {
                async fn encode_async<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
                    w.encode_buf(&(*self as u64).to_le_bytes()).await
                }
            }

            impl AsyncSiaDecodable for $t {
                async fn decode_async<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error> {
                    let mut buf = [0u8; 8];
                    r.decode_buf(&mut buf).await?;
                    Ok(u64::from_le_bytes(buf) as Self)
                }
            }
        )*
    }
}

impl_sia_numeric!(u16, u32, usize, i16, i32, i64, u64);

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    async fn test_roundtrip<T: AsyncSiaEncodable + AsyncSiaDecodable + Debug + PartialEq>(
        value: T,
        expected_bytes: Vec<u8>,
    ) {
        let mut encoded_bytes = Vec::new();
        value
            .encode_async(&mut encoded_bytes)
            .await
            .unwrap_or_else(|e| panic!("failed to encode: {e:?}"));

        assert_eq!(
            encoded_bytes, expected_bytes,
            "encoding mismatch for {value:?}"
        );

        let mut bytes = &expected_bytes[..];
        let decoded = T::decode_async(&mut bytes)
            .await
            .unwrap_or_else(|e| panic!("failed to decode: {e:?}"));
        assert_eq!(decoded, value, "decoding mismatch for {value:?}");

        assert_eq!(bytes.len(), 0, "leftover bytes for {value:?}");
    }

    #[tokio::test]
    async fn test_numerics() {
        test_roundtrip(1u8, vec![1]).await;
        test_roundtrip(2u16, vec![2, 0, 0, 0, 0, 0, 0, 0]).await;
        test_roundtrip(3u32, vec![3, 0, 0, 0, 0, 0, 0, 0]).await;
        test_roundtrip(4u64, vec![4, 0, 0, 0, 0, 0, 0, 0]).await;
        test_roundtrip(5usize, vec![5, 0, 0, 0, 0, 0, 0, 0]).await;
        test_roundtrip(-1i16, vec![255, 255, 255, 255, 255, 255, 255, 255]).await;
        test_roundtrip(-2i32, vec![254, 255, 255, 255, 255, 255, 255, 255]).await;
        test_roundtrip(-3i64, vec![253, 255, 255, 255, 255, 255, 255, 255]).await;
    }

    #[tokio::test]
    async fn test_strings() {
        test_roundtrip(
            "hello".to_string(),
            vec![
                5, 0, 0, 0, 0, 0, 0, 0, // length prefix
                104, 101, 108, 108, 111, // "hello"
            ],
        )
        .await;
        test_roundtrip(
            "".to_string(),
            vec![0, 0, 0, 0, 0, 0, 0, 0], // empty string length
        )
        .await;
    }

    #[tokio::test]
    async fn test_fixed_arrays() {
        test_roundtrip([1u8, 2u8, 3u8], vec![1, 2, 3]).await;
        test_roundtrip([0u8; 4], vec![0, 0, 0, 0]).await;
    }

    #[tokio::test]
    async fn test_vectors() {
        test_roundtrip(
            vec![1u8, 2u8, 3u8],
            vec![
                3, 0, 0, 0, 0, 0, 0, 0, // length prefix
                1, 2, 3, // values
            ],
        )
        .await;
        test_roundtrip(
            vec![100u64, 200u64],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // length prefix
                100, 0, 0, 0, 0, 0, 0, 0, // 100u64
                200, 0, 0, 0, 0, 0, 0, 0, // 200u64
            ],
        )
        .await;
        test_roundtrip(
            vec!["a".to_string(), "bc".to_string()],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // vector length
                1, 0, 0, 0, 0, 0, 0, 0,  // first string length
                97, // "a"
                2, 0, 0, 0, 0, 0, 0, 0, // second string length
                98, 99, // "bc"
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_nested() {
        test_roundtrip(
            vec![vec![1u8, 2u8], vec![3u8, 4u8]],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // outer vec length
                2, 0, 0, 0, 0, 0, 0, 0, // first inner vec length
                1, 2, // first inner vec contents
                2, 0, 0, 0, 0, 0, 0, 0, // second inner vec length
                3, 4, // second inner vec contents
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_bytes() {
        test_roundtrip(
            Bytes::from("hello"),
            vec![
                5, 0, 0, 0, 0, 0, 0, 0, // length prefix
                104, 101, 108, 108, 111, // "hello"
            ],
        )
        .await;
        test_roundtrip(
            Bytes::from(""),
            vec![0, 0, 0, 0, 0, 0, 0, 0], // empty string length
        )
        .await;
    }
}
