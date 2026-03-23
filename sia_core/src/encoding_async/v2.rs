use super::Error as EncodingError;
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Duration, Utc};
use tokio::io::{AsyncRead, AsyncReadExt};

pub trait AsyncSiaDecodable: Sized {
    fn decode_async<R: AsyncRead + Unpin>(
        r: &mut R,
    ) -> impl Future<Output = Result<Self, EncodingError>>;
}

impl AsyncSiaDecodable for u8 {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let mut buf = [0; 1];
        r.read_exact(&mut buf).await?;
        Ok(buf[0])
    }
}

impl AsyncSiaDecodable for bool {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        match u8::decode_async(r).await? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(EncodingError::InvalidValue("requires 0 or 1".into())),
        }
    }
}

impl AsyncSiaDecodable for DateTime<Utc> {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let timestamp = i64::decode_async(r).await?;
        DateTime::from_timestamp_secs(timestamp)
            .ok_or_else(|| EncodingError::InvalidValue(format!("invalid timestamp: {timestamp}")))
    }
}

impl AsyncSiaDecodable for Duration {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let ns = u64::decode_async(r).await?;
        if ns > i64::MAX as u64 {
            return Err(EncodingError::InvalidValue(format!(
                "duration {ns} must be less than {}",
                i64::MAX
            )));
        }
        Ok(Duration::nanoseconds(ns as i64))
    }
}

impl AsyncSiaDecodable for Bytes {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let len = usize::decode_async(r).await?;
        let mut buf = BytesMut::zeroed(len);
        r.read_exact(&mut buf).await?;
        Ok(buf.freeze())
    }
}

impl<T: AsyncSiaDecodable> AsyncSiaDecodable for Option<T> {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        match bool::decode_async(r).await? {
            true => Ok(Some(T::decode_async(r).await?)),
            false => Ok(None),
        }
    }
}

impl<T: AsyncSiaDecodable> AsyncSiaDecodable for Vec<T> {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let mut vec = Vec::new();
        // note: the vec is not pre-allocated
        // to prevent abuse by sending a large len
        for _ in 0..usize::decode_async(r).await? {
            vec.push(T::decode_async(r).await?);
        }
        Ok(vec)
    }
}

impl AsyncSiaDecodable for String {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let bytes = Vec::<u8>::decode_async(r).await?;
        String::from_utf8(bytes).map_err(|e| EncodingError::InvalidValue(e.to_string()))
    }
}

impl<const N: usize> AsyncSiaDecodable for [u8; N] {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        let mut arr = [0u8; N];
        r.read_exact(&mut arr).await?;
        Ok(arr)
    }
}

macro_rules! impl_sia_numeric {
    ($($t:ty),*) => {
        $(
            impl AsyncSiaDecodable for $t {
                async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
                    let mut buf = [0u8; 8];
                    r.read_exact(&mut buf).await?;
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
    use crate::encoding::SiaEncodable;

    async fn test_decode<T: SiaEncodable + AsyncSiaDecodable + Debug + PartialEq>(
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
        let decoded = T::decode_async(&mut bytes)
            .await
            .unwrap_or_else(|e| panic!("failed to decode: {e:?}"));
        assert_eq!(decoded, value, "decoding mismatch for {value:?}");

        assert_eq!(bytes.len(), 0, "leftover bytes for {value:?}");
    }

    #[tokio::test]
    async fn test_numerics() {
        test_decode(1u8, vec![1]).await;
        test_decode(2u16, vec![2, 0, 0, 0, 0, 0, 0, 0]).await;
        test_decode(3u32, vec![3, 0, 0, 0, 0, 0, 0, 0]).await;
        test_decode(4u64, vec![4, 0, 0, 0, 0, 0, 0, 0]).await;
        test_decode(5usize, vec![5, 0, 0, 0, 0, 0, 0, 0]).await;
        test_decode(-1i16, vec![255, 255, 255, 255, 255, 255, 255, 255]).await;
        test_decode(-2i32, vec![254, 255, 255, 255, 255, 255, 255, 255]).await;
        test_decode(-3i64, vec![253, 255, 255, 255, 255, 255, 255, 255]).await;
    }

    #[tokio::test]
    async fn test_strings() {
        test_decode(
            "hello".to_string(),
            vec![5, 0, 0, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111],
        )
        .await;
        test_decode("".to_string(), vec![0, 0, 0, 0, 0, 0, 0, 0]).await;
    }

    #[tokio::test]
    async fn test_fixed_arrays() {
        test_decode([1u8, 2u8, 3u8], vec![1, 2, 3]).await;
        test_decode([0u8; 4], vec![0, 0, 0, 0]).await;
    }

    #[tokio::test]
    async fn test_vectors() {
        test_decode(vec![1u8, 2u8, 3u8], vec![3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]).await;
        test_decode(
            vec![100u64, 200u64],
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_bytes() {
        test_decode(
            Bytes::from("hello"),
            vec![5, 0, 0, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111],
        )
        .await;
        test_decode(Bytes::from(""), vec![0, 0, 0, 0, 0, 0, 0, 0]).await;
    }
}
