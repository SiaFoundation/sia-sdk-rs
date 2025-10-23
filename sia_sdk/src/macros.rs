// Macro to implement types used as identifiers which are 32 byte hashes and are
// serialized with a prefix
macro_rules! impl_hash_id {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            $crate::encoding_async::AsyncSiaEncode,
            $crate::encoding_async::AsyncSiaDecode,
            $crate::encoding::SiaEncode,
            $crate::encoding::SiaDecode,
            $crate::encoding::V1SiaEncode,
            $crate::encoding::V1SiaDecode,
        )]
        pub struct $name([u8; 32]);

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    String::serialize(&self.to_string(), serializer)
                } else {
                    <[u8; 32]>::serialize(&self.0, serializer)
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                s.parse()
                    .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
            }
        }

        impl $name {
            pub const fn new(b: [u8; 32]) -> Self {
                Self(b)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        impl From<blake2b_simd::Hash> for $name {
            fn from(hash: blake2b_simd::Hash) -> Self {
                let mut h = [0; 32];
                h.copy_from_slice(&hash.as_bytes()[..32]);
                Self(h)
            }
        }

        impl From<crate::blake2::Output> for $name {
            fn from(output: crate::blake2::Output) -> Self {
                let mut h = [0; 32];
                h.copy_from_slice(&output[..32]);
                Self(h)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(data: [u8; 32]) -> Self {
                $name(data)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(hash: $name) -> [u8; 32] {
                hash.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::types::HexParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let s = match s.split_once(':') {
                    Some((_prefix, suffix)) => suffix,
                    None => s,
                };

                if s.len() != 64 {
                    return Err($crate::types::HexParseError::InvalidLength(s.len()));
                }

                let mut data = [0u8; 32];
                hex::decode_to_slice(s, &mut data)
                    .map_err($crate::types::HexParseError::HexError)?;
                Ok($name(data))
            }
        }

        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name([0; 32])
            }
        }
    };
}
pub(crate) use impl_hash_id;

#[inline]
pub(crate) const fn decode_hex_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[inline]
pub(crate) const fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let hi = decode_hex_char(hi);
    let lo = decode_hex_char(lo);
    match (hi, lo) {
        (Some(hi), Some(lo)) => Some((hi << 4) | lo),
        _ => None,
    }
}

#[inline]
#[doc(hidden)]
pub const fn decode_hex_256(input: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut i = 0;
    while i < 64 {
        match decode_hex_pair(input[i], input[i + 1]) {
            Some(byte) => result[i / 2] = byte,
            _ => panic!("invalid hex char"),
        }
        i += 2;
    }
    result
}

#[inline]
#[doc(hidden)]
pub const fn decode_hex_512(input: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];
    let mut i = 0;
    while i < 128 {
        match decode_hex_pair(input[i], input[i + 1]) {
            Some(byte) => result[i / 2] = byte,
            _ => panic!("invalid hex char"),
        }
        i += 2;
    }
    result
}

/// A macro to create an Address from a literal hex string. The string must be 76 characters long.
///
/// The checksum is not verified.
/// ```
/// use sia::types::Address;
/// use sia::address;
///
/// const addr: Address = address!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0");
/// ```
#[macro_export]
macro_rules! address {
    ($text:literal) => {{
        if $text.len() != 76 {
            panic!("Address must be 76 characters");
        }
        $crate::types::Address::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a Hash256 from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia::types::Hash256;
/// use sia::hash_256;
///
/// const h: Hash256 = hash_256!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! hash_256 {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("Hash256 must be 64 characters");
        }
        $crate::types::Hash256::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a SiacoinOutputID from a literal hex string. The string must be 64 characters long.
///
///```
/// use sia::types::SiacoinOutputID;
/// use sia::siacoin_id;
///
/// const scoid: SiacoinOutputID = siacoin_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! siacoin_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("SiacoinOutputID must be 64 characters");
        }
        $crate::types::SiacoinOutputID::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a SiafundOutputID from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia::types::SiafundOutputID;
/// use sia::siafund_id;
///
/// const sfoid: SiafundOutputID = siafund_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! siafund_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("SiafundOutputID must be 64 characters");
        }
        $crate::types::SiafundOutputID::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a FileContractID from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia::types::FileContractID;
/// use sia::contract_id;
///
/// const fcid: FileContractID = contract_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! contract_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("FileContractID must be 64 characters");
        }
        $crate::types::FileContractID::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a TransactionID from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia::types::TransactionID;
/// use sia::transaction_id;
///
/// const txid: TransactionID = transaction_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! transaction_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("TransactionID must be 64 characters");
        }
        $crate::types::TransactionID::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a BlockID from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia::types::BlockID;
/// use sia::block_id;
///
/// const bid: BlockID = block_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! block_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("BlockID must be 64 characters");
        }
        $crate::types::BlockID::new($crate::macros::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a PublicKey from a literal hex string. The string must be 72 characters long and start with "ed25519:".
///
/// ```
/// use sia::signing::PublicKey;
/// use sia::public_key;
///
/// const pk: PublicKey = public_key!("ed25519:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c");
/// ```
#[macro_export]
macro_rules! public_key {
    ($text:literal) => {{
        if $text.len() != 72 {
            panic!("PublicKey must be 72 characters");
        }
        const ED25519_PREFIX: &[u8; 8] = b"ed25519:";

        let buf = $text.as_bytes();
        let mut s = [0u8; 64];
        let mut i = 0;
        while i < 72 {
            if i < 8 {
                if buf[i] != ED25519_PREFIX[i] {
                    panic!("PublicKey must start with ed25519:")
                }
            } else {
                s[i - 8] = buf[i];
            }
            i += 1;
        }

        $crate::signing::PublicKey::new($crate::macros::decode_hex_256(&s))
    }};
}

/// A macro to create a BlockID from a literal hex string. The string must be 64 characters long.
///
/// ```
/// use sia::signing::Signature;
/// use sia::signature;
///
/// const sig: Signature = signature!("458283fd707c9d170d5e1814944f35893c53c9445fd46c74a6b285bf3029bf404c9af509ea271d811726bd20d8c7d8fe4b9efdc4bebb445f18059eca886ece03");
/// ```
#[macro_export]
macro_rules! signature {
    ($text:literal) => {{
        if $text.len() != 128 {
            panic!("Signature must be 128 characters");
        }
        $crate::signing::Signature::new($crate::macros::decode_hex_512($text.as_bytes()))
    }};
}

#[cfg(test)]
mod tests {
    use crate::signing::PublicKey;
    use crate::types::{
        Address, BlockID, FileContractID, SiacoinOutputID, SiafundOutputID, TransactionID,
    };

    const EXPECTED_BYTES: [u8; 32] = [
        94, 183, 15, 20, 19, 135, 223, 30, 46, 205, 67, 75, 34, 190, 80, 191, 245, 122, 110, 8, 72,
        79, 56, 144, 254, 68, 21, 166, 211, 35, 181, 233,
    ];

    #[test]
    fn test_address_macro() {
        const ADDRESS: Address = address!(
            "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34"
        );
        assert_eq!(ADDRESS.as_ref(), EXPECTED_BYTES);
    }

    #[test]
    #[should_panic]
    fn test_bad_address() {
        address!("5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4");
    }

    #[test]
    fn test_public_key_macro() {
        const PUBLIC_KEY: PublicKey =
            public_key!("ed25519:5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9");
        assert_eq!(PUBLIC_KEY.as_ref(), EXPECTED_BYTES);
    }

    #[test]
    fn test_block_id_macro() {
        const BLOCK_ID: BlockID =
            block_id!("5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9");
        assert_eq!(BLOCK_ID.as_ref(), EXPECTED_BYTES);
    }

    #[test]
    fn test_transaction_id_macro() {
        const TRANSACTION_ID: TransactionID =
            transaction_id!("5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9");
        assert_eq!(TRANSACTION_ID.as_ref(), EXPECTED_BYTES);
    }

    #[test]
    fn test_contract_id_macro() {
        const CONTRACT_ID: FileContractID =
            contract_id!("5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9");
        assert_eq!(CONTRACT_ID.as_ref(), EXPECTED_BYTES);
    }

    #[test]
    fn test_siacoin_id_macro() {
        const SIACOIN_ID: SiacoinOutputID =
            siacoin_id!("5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9");
        assert_eq!(SIACOIN_ID.as_ref(), EXPECTED_BYTES);
    }

    #[test]
    fn test_siafund_id_macro() {
        const SIAFUND_ID: SiafundOutputID =
            siafund_id!("5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9");
        assert_eq!(SIAFUND_ID.as_ref(), EXPECTED_BYTES);
    }
}
