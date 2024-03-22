use std::ops::Add;
use std::ops::Sub;
use std::ops::Mul;
use std::ops::Div;
use std::num::ParseIntError;
use std::str::FromStr;
use std::fmt;


// I miss untyped constants
const SIACOIN_PRECISION_I32: i32 = 24;
const SIACOIN_PRECISION_U32: u32 = 24;

// Currency represents a quantity of Siacoins as Hastings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Currency(u128);

impl Currency {
	pub fn new(value: u128) -> Self {
		Currency(value)
	}
}

impl Add for Currency {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		Self(self.0.checked_add(other.0).expect("overflow in addition"))
	}
}

impl Sub for Currency {
	type Output = Self;

	fn sub(self, other: Self) -> Self {
		Self(self.0.checked_sub(other.0).expect("underflow in subtraction"))
	}
}

impl Mul for Currency {
	type Output = Self;

	fn mul(self, other: Self) -> Self {
		Self(self.0.checked_mul(other.0).expect("overflow in multiplication"))
	}
}

impl Div for Currency {
	type Output = Self;

	fn div(self, other: Self) -> Self {
		Self(self.0.checked_div(other.0).expect("division by zero"))
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

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.0.to_string().as_str())
    }
} 

impl Into<String> for Currency {
	fn into(self) -> String {
		if self.0 == 0 {
			return "0 SC".to_string()
		}

		let value_string = self.0.to_string();
		let mut u = (value_string.len() - 1) / 3;
		if u < 4 {
			return format!("{} H", value_string)
		} else if u > 12 {
			u = 12;
		}

		let mant = &value_string[..value_string.len() - 3 * u];
		let frac = value_string[value_string.len()-u*3..].trim_end_matches('0');
		let unit = match u-4 {
			0 => "pS",
			1 => "nS",
			2 => "uS",
			3 => "mS",
			4 => "SC",
			5 => "KS",
			6 => "MS",
			7 => "GS",
			8 => "TS",
			_ => panic!("unexpected unit")
		};

		if frac.is_empty() {
			return format!("{} {}", mant, unit)
		}
		format!("{}.{} {}", mant, frac, unit)
	}
}

impl FromStr for Currency {
	type Err = CurrencyParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let i = s.find(|c: char| !c.is_digit(10) && c != '.').unwrap_or(s.len());
		let (value, unit) = s.split_at(i);
		let unit = unit.trim();

		if unit.is_empty() || unit == "H" {
			let value = value.parse::<u128>()?;
			return Ok(Currency::new(value))
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
			return Err(CurrencyParseError::InvalidFormat("too many decimal points".to_string()))
		}

		let integer_part = parts[0].parse::<u128>().map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?;
		let fraction_part = if parts.len() == 2 {
			parts[1].parse::<u128>().map_err(|_| CurrencyParseError::InvalidFormat("invalid integer part".to_string()))?
		} else {
			0
		};

		let frac_digits = parts.get(1).map_or(0, |frac| frac.len() as i32);
		let integer = integer_part * 10u128.pow((SIACOIN_PRECISION_I32 + scaling_factor) as u32);
		let fraction = fraction_part * 10u128.pow((SIACOIN_PRECISION_I32 - frac_digits + scaling_factor) as u32);

		Ok(Currency::new(integer+fraction))
	}
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
pub fn siacoins(n: u64) -> Currency {
	Currency::new((n as u128) * 10u128.pow(SIACOIN_PRECISION_U32))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_display() {
		let test_cases = vec![
			(Currency::new(1), "1 H"),
			(Currency::new(100), "100 H"),
			(Currency::new(1001), "1001 H"),
			(Currency::new(10000), "10000 H"),
			(siacoins(1)/Currency::new(1_000_000_000_000), "1 pS"),
			(siacoins(151212312)/Currency::new(1_000_000_000_000), "151.212312 uS"),
			(siacoins(1)/Currency::new(2), "500 mS"),
			(siacoins(1), "1 SC"),
			(siacoins(10), "10 SC"),
			(siacoins(100), "100 SC"),
			(siacoins(1000), "1 KS"),
			(siacoins(10000), "10 KS"),
			(siacoins(u16::MAX as u64), "65.535 KS"),
			(siacoins(10_0000), "100 KS"),
			(siacoins(1_000_000), "1 MS"),
			(siacoins(10_000_000), "10 MS"),
			(siacoins(100_000_000), "100 MS"),
			(siacoins(1_000_000_000), "1 GS"),
			(siacoins(u32::MAX as u64), "4.294967295 GS"),
			(siacoins(10_000_000_000), "10 GS"),
			(siacoins(100_000_000_000), "100 GS"),
			(siacoins(1_000_000_000_000), "1 TS"),
			(siacoins(10_000_000_000_000), "10 TS"),
			(siacoins(100_000_000_000_000), "100 TS"),
			(siacoins(10) - Currency::new(1), "9.999999999999999999999999 SC"),
			(Currency::new(50_587_566_000_000_000_000_000_000),"50.587566 SC"),
			(Currency::new(2529378333356156158367), "2.529378333356156158367 mS"),
			(Currency::new(u128::MAX), "340.282366920938463463374607431768211455 TS"),
		];

		for (currency, expected) in test_cases {
			assert_eq!(currency.to_string(), expected);
		}
	}
	
	#[test]
	fn test_from_str() {
		let test_cases = vec![
			("1 H", Currency::new(1)),
			("100 H", Currency::new(100)),
			("1001 H", Currency::new(1001)),
			("10000 H", Currency::new(10000)),
			("1 pS", siacoins(1)/Currency::new(1_000_000_000_000)),
			("151.212312 uS", siacoins(151212312)/Currency::new(1_000_000_000_000)),
			("500 mS", siacoins(1)/Currency::new(2)),
			("1 SC", siacoins(1)),
			("10 SC", siacoins(10)),
			("100 SC", siacoins(100)),
			("1 KS", siacoins(1000)),
			("10 KS", siacoins(10000)),
			("65.535 KS", siacoins(u16::MAX as u64)),
			("100 KS", siacoins(100000)),
			("1 MS", siacoins(1000000)),
			("10 MS", siacoins(10000000)),
			("100 MS", siacoins(100000000)),
			("1 GS", siacoins(1000000000)),
			("4.294967295 GS", siacoins(u32::MAX as u64)),
			("10 GS", siacoins(10000000000)),
			("100 GS", siacoins(100000000000)),
			("1 TS", siacoins(1000000000000)),
			("10 TS", siacoins(10000000000000)),
			("100 TS", siacoins(100000000000000)),
			("9.999999999999999999999999 SC", siacoins(10) - Currency::new(1)),
			("50.587566 SC", Currency::new(50587566000000000000000000)),
			("2.529378333356156158367 mS", Currency::new(2529378333356156158367)),
			("340.282366920938463463374607431768211455 TS", Currency::new(u128::MAX)),
		];
		for (input, expected) in test_cases {
			assert_eq!(input.parse::<Currency>().unwrap(), expected);
		}
	}
}