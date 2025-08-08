use crate::encoding::{
    SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode, V1SiaEncodable,
    V1SiaEncode,
};
use core::{fmt, str};
use serde::{Deserialize, Serialize};

pub const SPECIFIER_SIZE: usize = 16;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Serialize,
    Deserialize,
    SiaEncode,
    V1SiaEncode,
    V1SiaDecode,
    SiaDecode,
)]
pub struct Specifier([u8; SPECIFIER_SIZE]);

impl Specifier {
    pub const fn new(buf: [u8; SPECIFIER_SIZE]) -> Self {
        Self(buf)
    }
}

impl AsRef<[u8]> for Specifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&str> for Specifier {
    fn from(s: &str) -> Self {
        let mut buf = [0; SPECIFIER_SIZE];
        let src = s.as_bytes();
        let len = src.len();
        let index = len.min(SPECIFIER_SIZE);
        buf[..index].copy_from_slice(&src[..index]);
        Self(buf)
    }
}

impl fmt::Display for Specifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // get the last non-zero byte or 0 if all bytes are 0
        let index = self
            .0
            .iter()
            .rev()
            .position(|&x| x != 0)
            .map_or(0, |pos| SPECIFIER_SIZE - pos);
        let str = str::from_utf8(&self.0[..index]).map_err(|_| fmt::Error)?;
        write!(f, "{str}")
    }
}

macro_rules! specifier {
    ($text:expr) => {{
        let src = $text.as_bytes();
        let len = src.len();
        assert!(len <= $crate::types::SPECIFIER_SIZE, "specifier too long");
        let mut buf = [0; 16];
        let mut index: usize = 0;
        while index < len {
            buf[index] = src[index];
            index += 1;
        }
        $crate::types::Specifier::new(buf)
    }};
}
pub(crate) use specifier;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specifier() {
        let spec = specifier!["hello"];
        let expected = Specifier([
            b'h', b'e', b'l', b'l', b'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(spec, expected);
    }

    #[test]
    fn test_specifier_string() {
        let test_cases = vec![
            (specifier!["hello world"], "hello world"),
            (specifier!["hello"], "hello"),
            (
                Specifier::new([
                    b'h', b'e', b'l', b'l', b'o', 0, b'w', b'o', b'r', b'l', b'd', 0, 0, 0, 0, 0,
                ]),
                "hello\0world",
            ),
            (Specifier::new([0; 16]), ""),
        ];
        for (specifier, expected) in test_cases {
            assert_eq!(specifier.to_string(), expected);
        }
    }
}
