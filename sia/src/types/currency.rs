use core::num::ParseIntError;
use core::ops::{Add, Deref, DerefMut, Div, Mul, Rem, Sub};
use std::io::Write;
use std::iter::Sum;

use serde::{Deserialize, Serialize};

use crate::encoding::{self, SiaDecodable, SiaEncodable, V1SiaDecodable, V1SiaEncodable};

// I miss untyped constants
const SIACOIN_PRECISION_I32: i32 = 24;
const SIACOIN_PRECISION_U32: u32 = 24;

// Currency represents a quantity of Siacoins as Hastings.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Currency(u128);

impl Serialize for Currency {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CurrencyVisitor;

        impl serde::de::Visitor<'_> for CurrencyVisitor {
            type Value = Currency;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or numeric representing a currency value")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Currency::parse_string(s).map_err(|e| serde::de::Error::custom(format!("{e:?}")))
            }

            fn visit_i32<E: serde::de::Error>(self, value: i32) -> Result<Self::Value, E> {
                if value < 0 {
                    return Err(serde::de::Error::custom("currency value must be positive"));
                }
                Ok(Currency::new(value as u128))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                if value < 0 {
                    return Err(serde::de::Error::custom("currency value must be positive"));
                }
                Ok(Currency::new(value as u128))
            }

            fn visit_i128<E: serde::de::Error>(self, value: i128) -> Result<Self::Value, E> {
                if value < 0 {
                    return Err(serde::de::Error::custom("currency value must be positive"));
                }
                Ok(Currency::new(value as u128))
            }

            fn visit_u32<E: serde::de::Error>(self, value: u32) -> Result<Self::Value, E> {
                Ok(Currency::new(value as u128))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(Currency::new(value as u128))
            }

            fn visit_u128<E: serde::de::Error>(self, value: u128) -> Result<Self::Value, E> {
                Ok(Currency::new(value))
            }
        }

        deserializer.deserialize_any(CurrencyVisitor)
    }
}

impl V1SiaEncodable for Currency {
    fn encode_v1<W: Write>(&self, w: &mut W) -> encoding::Result<()> {
        let currency_buf = self.to_be_bytes();
        let i = currency_buf
            .iter()
            .enumerate()
            .find(|&(_index, &value)| value != 0)
            .map_or(16, |(index, _value)| index); // 16 if all bytes are 0
        currency_buf[i..].encode_v1(w)
    }
}

impl V1SiaDecodable for Currency {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let len = usize::decode_v1(r)?;
        if len > 16 {
            return Err(encoding::Error::InvalidLength);
        }
        let mut buf = [0u8; 16];
        r.read_exact(&mut buf[16 - len..])?;
        Ok(Currency(u128::from_be_bytes(buf)))
    }
}

impl SiaEncodable for Currency {
    fn encode<W: Write>(&self, w: &mut W) -> encoding::Result<()> {
        w.write_all(&self.0.to_le_bytes())?;
        Ok(())
    }
}

impl SiaDecodable for Currency {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let mut buf = [0u8; 16];
        r.read_exact(&mut buf)?;
        Ok(Currency(u128::from_le_bytes(buf)))
    }
}

// Implement Deref and DerefMut to be able to implicitly use Currency as a u128
// This gives us all the traits that u128 already implements for free.
impl Deref for Currency {
    type Target = u128;
    fn deref(&self) -> &u128 {
        &self.0
    }
}

impl DerefMut for Currency {
    fn deref_mut(&mut self) -> &mut u128 {
        &mut self.0
    }
}

impl TryInto<u64> for Currency {
    type Error = core::num::TryFromIntError;
    fn try_into(self) -> Result<u64, Self::Error> {
        self.0.try_into()
    }
}

// Implement AsRef as well to be able to implicitly obtain a &u128 from a Currency as well.
impl<T> AsRef<T> for Currency
where
    T: ?Sized,
    <Currency as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl Currency {
    pub const fn new(value: u128) -> Self {
        Currency(value)
    }

    pub const fn zero() -> Self {
        Currency(0)
    }

    pub fn parse_string(s: &str) -> Result<Self, CurrencyParseError> {
        let i = s
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len());
        let (value, unit) = s.split_at(i);
        let value = value.trim();
        let unit = unit.trim();

        if unit.is_empty() || unit == "H" {
            let value = value.parse::<u128>()?;
            return Ok(Currency::new(value));
        }

        let scaling_factor: i32 = match unit {
            "pS" => -12,
            "nS" => -9,
            "uS" => -6,
            "mS" => -3,
            "SC" => 0,
            "KS" => 3,
            "MS" => 6,
            "GS" => 9,
            "TS" => 12,
            &_ => return Err(CurrencyParseError::InvalidUnit(unit.to_string())),
        };

        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() > 2 {
            return Err(CurrencyParseError::InvalidFormat(
                "too many decimal points".to_string(),
            ));
        }

        let integer_part = parts[0]
            .parse::<u128>()
            .map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?;
        let fraction_part = if parts.len() == 2 {
            parts[1].parse::<u128>().map_err(|_| {
                CurrencyParseError::InvalidFormat("invalid integer part".to_string())
            })?
        } else {
            0
        };

        let frac_digits = parts.get(1).map_or(0, |frac| frac.len() as i32);
        let integer = integer_part * 10u128.pow((SIACOIN_PRECISION_I32 + scaling_factor) as u32);
        let fraction = fraction_part
            * 10u128.pow((SIACOIN_PRECISION_I32 - frac_digits + scaling_factor) as u32);

        Ok(Currency::new(integer + fraction))
    }

    /// Converts a given amount of Siacoins into the `Currency` type.
    ///
    /// This function takes the amount of Siacoins as a `u64` and converts it into
    /// the `Currency` type, which internally represents the value in Hastings where
    /// 1 SC = 10^24 H.
    ///
    /// # Arguments
    ///
    /// * `n` - The amount of Siacoins to be converted into `Currency`.
    ///
    /// # Returns
    ///
    /// Returns a `Currency` instance representing the specified amount of Siacoins.
    pub const fn siacoins(n: u64) -> Self {
        Currency::new((n as u128) * 10u128.pow(SIACOIN_PRECISION_U32))
    }

    pub fn checked_add(self, other: Currency) -> Option<Self> {
        let v = self.0.checked_add(other.0)?;
        Some(Currency(v))
    }

    pub fn checked_sub(self, other: Currency) -> Option<Self> {
        let v = self.0.checked_sub(other.0)?;
        Some(Currency(v))
    }

    pub fn checked_mul(self, other: Currency) -> Option<Self> {
        let v = self.0.checked_mul(other.0)?;
        Some(Currency(v))
    }

    pub fn checked_div(self, other: Currency) -> Option<Self> {
        let v = self.0.checked_div(other.0)?;
        Some(Currency(v))
    }
}

impl Add for Currency {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub for Currency {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Mul for Currency {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl Div for Currency {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl Sum for Currency {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Currency::new(0), Add::add)
    }
}

impl Rem for Currency {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self(self.0 % rhs.0)
    }
}

#[derive(Debug, PartialEq)]
pub enum CurrencyParseError {
    ParseIntErr(ParseIntError),
    InvalidUnit(String),
    InvalidFormat(String),
}

impl From<ParseIntError> for CurrencyParseError {
    fn from(err: ParseIntError) -> Self {
        CurrencyParseError::ParseIntErr(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let test_cases = vec![
            ("1 H", Currency::new(1)),
            ("100 H", Currency::new(100)),
            ("1001 H", Currency::new(1001)),
            ("10000 H", Currency::new(10000)),
            (
                "1 pS",
                Currency::siacoins(1) / Currency::new(1_000_000_000_000),
            ),
            (
                "151.212312 uS",
                Currency::siacoins(151212312) / Currency::new(1_000_000_000_000),
            ),
            ("500 mS", Currency::siacoins(1) / Currency::new(2)),
            ("1 SC", Currency::siacoins(1)),
            ("10 SC", Currency::siacoins(10)),
            ("100 SC", Currency::siacoins(100)),
            ("1 KS", Currency::siacoins(1000)),
            ("10 KS", Currency::siacoins(10000)),
            ("65.535 KS", Currency::siacoins(u16::MAX as u64)),
            ("100KS", Currency::siacoins(100000)),
            ("1 MS", Currency::siacoins(1000000)),
            ("10 MS", Currency::siacoins(10000000)),
            ("100 MS", Currency::siacoins(100000000)),
            ("1 GS", Currency::siacoins(1000000000)),
            ("4.294967295GS", Currency::siacoins(u32::MAX as u64)),
            ("10 GS", Currency::siacoins(10000000000)),
            ("100 GS", Currency::siacoins(100000000000)),
            ("1 TS", Currency::siacoins(1000000000000)),
            ("10 TS", Currency::siacoins(10000000000000)),
            ("100 TS", Currency::siacoins(100000000000000)),
            (
                "9.999999999999999999999999 SC",
                Currency::siacoins(10) - Currency::new(1),
            ),
            ("50.587566 SC", Currency::new(50587566000000000000000000)),
            (
                "2.529378333356156158367 mS",
                Currency::new(2529378333356156158367),
            ),
            (
                "340.282366920938463463374607431768211455 TS",
                Currency::new(u128::MAX),
            ),
        ];
        for (input, expected) in test_cases {
            assert_eq!(Currency::parse_string(input).unwrap(), expected);
        }
    }

    #[test]
    fn test_encode_v1() {
        let test_cases = vec![
            (Currency::new(0), vec![0, 0, 0, 0, 0, 0, 0, 0]),
            (Currency::new(10000), vec![2, 0, 0, 0, 0, 0, 0, 0, 39, 16]),
            (
                Currency::new(50587566000000000000000000),
                vec![
                    11, 0, 0, 0, 0, 0, 0, 0, 41, 216, 85, 114, 169, 108, 83, 1, 248, 0, 0,
                ],
            ),
            (
                Currency::new(2529378333356156158367),
                vec![
                    9, 0, 0, 0, 0, 0, 0, 0, 137, 30, 45, 0, 247, 119, 66, 129, 159,
                ],
            ),
            (
                Currency::new(340282366920938463463374607431768211455),
                vec![
                    16, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255,
                ],
            ),
        ];

        for (currency, expected) in test_cases {
            let mut serialized_currency = Vec::new();
            currency
                .encode_v1(&mut serialized_currency)
                .unwrap_or_else(|e| panic!("failed to encode: {e:?}"));
            assert_eq!(serialized_currency, expected, "failed for {currency:?}");
            let deserialized_currency = Currency::decode_v1(&mut &serialized_currency[..])
                .unwrap_or_else(|e| panic!("failed to decode: {e:?}"));
            assert_eq!(deserialized_currency, currency, "failed for {currency:?}");
        }
    }

    #[test]
    fn test_json_serialize_currency() {
        let currency_num = 120282366920938463463374607431768211455;
        let currency = Currency::new(currency_num);

        // json
        let currency_serialized = serde_json::to_string(&currency).unwrap();
        let currency_deserialized: Currency = serde_json::from_str(&currency_serialized).unwrap();
        assert_eq!(currency_serialized, format!("\"{currency_num}\""));
        assert_eq!(currency_deserialized, currency);
    }
}
