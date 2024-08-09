use core::fmt;
use std::time::SystemTime;

use crate::{ChainIndex, Hash256, HexParseError};
use base64::prelude::*;
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::Error, Deserialize, Serialize};

/// An ed25519 public key that can be used to verify a signature
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    const PREFIX: &'static str = "ed25519:";
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            String::serialize(
                &format!("{}{}", Self::PREFIX, &self.to_string()),
                serializer,
            )
        } else {
            <[u8; 32]>::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let s = s.strip_prefix(Self::PREFIX).ok_or(Error::custom(format!(
                "key must have prefix '{}'",
                Self::PREFIX
            )))?;
            let mut pk = [0; 32];
            hex::decode_to_slice(s, &mut pk).map_err(|e| Error::custom(format!("{:?}", e)))?;
            Ok(Self::new(pk))
        } else {
            Ok(PublicKey(<[u8; 32]>::deserialize(deserializer)?))
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl PublicKey {
    pub fn new(buf: [u8; 32]) -> Self {
        PublicKey(buf)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let pk = VerifyingKey::from_bytes(&self.0).unwrap();
        pk.verify(msg, &ED25519Signature::from_bytes(signature.as_ref()))
            .is_ok()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An ed25519 private key that can be used to sign a hash
#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey([u8; 64]);

impl PrivateKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(seed);
        PrivateKey(sk.to_keypair_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[32..]);
        PublicKey::new(buf)
    }

    pub fn sign(&self, buf: &[u8]) -> Signature {
        let sk = SigningKey::from_bytes(&self.0[..32].try_into().unwrap());
        Signature::new(sk.sign(buf).to_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 64]> for PrivateKey {
    fn from(key: [u8; 64]) -> Self {
        PrivateKey(key)
    }
}

impl From<Hash256> for PrivateKey {
    fn from(hash: Hash256) -> Self {
        PrivateKey::from_seed(hash.as_ref())
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zero out the private key
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            String::serialize(&BASE64_STANDARD.encode(self.0), serializer)
        } else {
            <[u8]>::serialize(&self.0, serializer) // prefixed with length
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let sig = BASE64_STANDARD
                .decode(s)
                .map_err(|e| D::Error::custom(format!("{:?}", e)))?;
            if sig.len() != 64 {
                return Err(D::Error::custom("Invalid signature length"));
            }
            Ok(Signature(sig.try_into().unwrap()))
        } else {
            let data = <Vec<u8>>::deserialize(deserializer)?;
            if data.len() != 64 {
                return Err(D::Error::custom("Invalid signature length"));
            }
            Ok(Signature(data.try_into().unwrap()))
        }
    }
}

impl Signature {
    pub fn new(sig: [u8; 64]) -> Self {
        Signature(sig)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let s = match s.split_once(':') {
            Some((_prefix, suffix)) => suffix,
            None => s,
        };

        let data = hex::decode(s).map_err(HexParseError::HexError)?;
        if data.len() != 64 {
            return Err(HexParseError::InvalidLength);
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data);
        Ok(Signature(sig))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0; 64])
    }
}

impl AsRef<[u8; 64]> for Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sig:{}", hex::encode(self.0))
    }
}
#[derive(Default, Debug)]
pub struct NetworkHardforks {
    pub asic_height: u64,

    pub foundation_height: u64,

    pub v2_allow_height: u64,
    pub v2_require_height: u64,
}

pub struct SigningState {
    pub index: ChainIndex,
    pub median_timestamp: SystemTime,
    pub hardforks: NetworkHardforks,
}

impl SigningState {
    pub fn new(
        index: ChainIndex,
        median_timestamp: SystemTime,
        hardforks: NetworkHardforks,
    ) -> Self {
        SigningState {
            index,
            median_timestamp,
            hardforks,
        }
    }

    pub fn replay_prefix(&self) -> &[u8] {
        if self.index.height >= self.hardforks.v2_allow_height {
            return &[2];
        } else if self.index.height >= self.hardforks.foundation_height {
            return &[1];
        } else if self.index.height >= self.hardforks.asic_height {
            return &[0];
        }
        &[]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encoding::{from_reader, to_bytes},
        transactions::Transaction,
    };

    use super::*;

    #[test]
    fn test_serialize_publickey() {
        let public_key_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let public_key = PublicKey::new(hex::decode(public_key_str).unwrap().try_into().unwrap());

        // binary
        let public_key_serialized = to_bytes(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            from_reader(&mut &public_key_serialized[..]).unwrap();
        assert_eq!(public_key_serialized, hex::decode(public_key_str).unwrap());
        assert_eq!(public_key_deserialized, public_key);

        // json
        let public_key_serialized = serde_json::to_string(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            serde_json::from_str(&public_key_serialized).unwrap();
        assert_eq!(
            public_key_serialized,
            format!("\"ed25519:{0}\"", public_key_str)
        );
        assert_eq!(public_key_deserialized, public_key);
    }

    #[test]
    fn test_transaction_sign_verify() {
        let raw_transaction = [
            1, 0, 0, 0, 0, 0, 0, 0, 60, 142, 227, 105, 15, 43, 39, 47, 97, 194, 240, 54, 246, 8,
            123, 43, 66, 4, 166, 68, 16, 51, 210, 130, 161, 228, 73, 244, 11, 187, 75, 81, 0, 0, 0,
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 117, 69, 139, 27, 176, 70, 189, 87, 202, 254, 163,
            222, 234, 222, 95, 107, 4, 191, 122, 31, 179, 4, 188, 19, 14, 153, 200, 60, 184, 14,
            186, 147, 1, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 8,
            19, 243, 151, 143, 137, 64, 152, 68, 0, 0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32,
            235, 88, 188, 80, 209, 228, 219, 88, 207, 210, 253, 199, 99, 251, 86, 213, 34, 7, 70,
            212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0, 8, 19, 243, 151, 143, 137, 64, 152, 68, 0,
            0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32, 235, 88, 188, 80, 209, 228, 219, 88, 207,
            210, 253, 199, 99, 251, 86, 213, 34, 7, 70, 212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0,
            8, 19, 243, 151, 143, 137, 64, 152, 68, 0, 0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32,
            235, 88, 188, 80, 209, 228, 219, 88, 207, 210, 253, 199, 99, 251, 86, 213, 34, 7, 70,
            212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0, 8, 19, 243, 151, 143, 137, 64, 152, 68, 0,
            0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32, 235, 88, 188, 80, 209, 228, 219, 88, 207,
            210, 253, 199, 99, 251, 86, 213, 34, 7, 70, 212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0,
            8, 19, 243, 151, 143, 137, 64, 152, 68, 0, 0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32,
            235, 88, 188, 80, 209, 228, 219, 88, 207, 210, 253, 199, 99, 251, 86, 213, 34, 7, 70,
            212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0, 8, 19, 243, 151, 143, 137, 64, 152, 68, 0,
            0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32, 235, 88, 188, 80, 209, 228, 219, 88, 207,
            210, 253, 199, 99, 251, 86, 213, 34, 7, 70, 212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0,
            8, 19, 243, 151, 143, 137, 64, 152, 68, 0, 0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32,
            235, 88, 188, 80, 209, 228, 219, 88, 207, 210, 253, 199, 99, 251, 86, 213, 34, 7, 70,
            212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0, 8, 19, 243, 151, 143, 137, 64, 152, 68, 0,
            0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32, 235, 88, 188, 80, 209, 228, 219, 88, 207,
            210, 253, 199, 99, 251, 86, 213, 34, 7, 70, 212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0,
            8, 19, 243, 151, 143, 137, 64, 152, 68, 0, 0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32,
            235, 88, 188, 80, 209, 228, 219, 88, 207, 210, 253, 199, 99, 251, 86, 213, 34, 7, 70,
            212, 202, 55, 243, 12, 0, 0, 0, 0, 0, 0, 0, 8, 19, 243, 151, 143, 137, 64, 152, 68, 0,
            0, 0, 122, 152, 5, 188, 240, 94, 6, 19, 32, 235, 88, 188, 80, 209, 228, 219, 88, 207,
            210, 253, 199, 99, 251, 86, 213, 34, 7, 70, 212, 202, 55, 243, 13, 0, 0, 0, 0, 0, 0, 0,
            3, 120, 145, 214, 24, 78, 112, 225, 220, 95, 64, 0, 0, 0, 35, 220, 64, 13, 118, 50, 82,
            106, 130, 240, 148, 221, 214, 6, 215, 187, 247, 150, 37, 30, 141, 44, 183, 17, 84, 85,
            2, 193, 245, 50, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0,
            0, 0, 0, 0, 0, 1, 69, 66, 186, 18, 163, 55, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let unsigned_transaction: Transaction = from_reader(&mut &raw_transaction[..]).unwrap();

        let key = PrivateKey::from([
            114, 152, 250, 154, 63, 214, 160, 97, 24, 74, 157, 172, 159, 191, 32, 141, 56, 178,
            117, 28, 166, 64, 121, 47, 18, 79, 248, 41, 232, 126, 231, 140, 94, 19, 124, 209, 145,
            85, 91, 26, 80, 172, 5, 203, 35, 91, 64, 126, 9, 173, 7, 54, 83, 206, 215, 33, 39, 150,
            60, 53, 203, 125, 192, 147,
        ]);

        let mut state = SigningState::new(
            ChainIndex {
                id: Default::default(),
                height: 1,
            },
            SystemTime::UNIX_EPOCH, // not relevant
            NetworkHardforks {
                asic_height: 10,
                foundation_height: 100,
                v2_allow_height: 1000,
                v2_require_height: 10000,
            },
        );

        // various test-cases for the individual hardfork heights
        struct test_case {
            height: u64,
            sig_hash: Hash256,
            signature: Signature,
        }
        let test_cases = [
            test_case {
                height: 1,
                sig_hash: Hash256::from([
                    103, 85, 177, 230, 217, 250, 31, 44, 58, 216, 0, 141, 201, 11, 110, 89, 30,
                    160, 234, 205, 28, 54, 126, 107, 70, 161, 172, 76, 140, 183, 82, 174,
                ]),
                signature: Signature([
                    117, 204, 154, 199, 43, 203, 72, 68, 205, 215, 177, 228, 209, 153, 249, 13, 54,
                    36, 52, 94, 246, 174, 180, 164, 85, 246, 148, 87, 77, 187, 114, 213, 150, 104,
                    201, 99, 60, 94, 84, 97, 212, 37, 145, 252, 90, 88, 47, 134, 222, 216, 192,
                    242, 220, 180, 120, 194, 162, 144, 26, 167, 193, 42, 29, 5,
                ]),
            },
            test_case {
                height: 10,
                sig_hash: Hash256::from([
                    71, 70, 128, 193, 162, 182, 181, 193, 105, 235, 111, 161, 28, 211, 124, 226,
                    141, 248, 216, 55, 70, 214, 50, 212, 133, 71, 147, 254, 58, 38, 0, 227,
                ]),
                signature: Signature([
                    41, 220, 18, 178, 144, 169, 73, 153, 44, 108, 77, 39, 40, 58, 162, 188, 93, 74,
                    99, 155, 97, 132, 198, 199, 248, 65, 1, 102, 238, 150, 59, 198, 230, 103, 60,
                    233, 127, 52, 85, 206, 170, 32, 214, 0, 254, 237, 124, 27, 179, 204, 105, 118,
                    98, 103, 42, 213, 49, 126, 193, 245, 14, 160, 164, 9,
                ]),
            },
            test_case {
                height: 100,
                sig_hash: Hash256::from([
                    91, 168, 132, 209, 109, 191, 250, 156, 220, 211, 230, 231, 96, 68, 19, 148, 26,
                    174, 49, 7, 67, 170, 90, 71, 77, 127, 18, 136, 110, 222, 176, 37,
                ]),
                signature: Signature([
                    141, 171, 186, 219, 207, 43, 207, 142, 220, 173, 184, 33, 57, 129, 77, 112, 28,
                    205, 107, 68, 114, 149, 208, 30, 145, 124, 121, 61, 218, 25, 82, 206, 157, 78,
                    163, 7, 226, 11, 118, 185, 98, 53, 146, 126, 217, 46, 240, 226, 196, 152, 211,
                    24, 63, 158, 82, 8, 25, 118, 170, 41, 229, 185, 122, 11,
                ]),
            },
            test_case {
                height: 1000,
                sig_hash: Hash256::from([
                    191, 24, 139, 35, 9, 235, 100, 7, 193, 151, 234, 37, 216, 152, 67, 2, 195, 192,
                    216, 181, 41, 167, 91, 63, 226, 84, 194, 207, 0, 26, 67, 45,
                ]),
                signature: Signature([
                    76, 165, 116, 181, 135, 120, 83, 45, 42, 22, 51, 45, 210, 190, 161, 128, 30,
                    235, 252, 254, 180, 206, 62, 223, 226, 221, 185, 55, 33, 69, 161, 45, 254, 120,
                    230, 142, 75, 78, 253, 24, 129, 57, 110, 34, 100, 245, 215, 115, 245, 68, 91,
                    160, 202, 228, 109, 158, 188, 86, 44, 25, 153, 254, 208, 12,
                ]),
            },
            test_case {
                height: 10000,
                sig_hash: Hash256::from([
                    191, 24, 139, 35, 9, 235, 100, 7, 193, 151, 234, 37, 216, 152, 67, 2, 195, 192,
                    216, 181, 41, 167, 91, 63, 226, 84, 194, 207, 0, 26, 67, 45,
                ]),
                signature: Signature([
                    76, 165, 116, 181, 135, 120, 83, 45, 42, 22, 51, 45, 210, 190, 161, 128, 30,
                    235, 252, 254, 180, 206, 62, 223, 226, 221, 185, 55, 33, 69, 161, 45, 254, 120,
                    230, 142, 75, 78, 253, 24, 129, 57, 110, 34, 100, 245, 215, 115, 245, 68, 91,
                    160, 202, 228, 109, 158, 188, 86, 44, 25, 153, 254, 208, 12,
                ]),
            },
        ];

        for tc in test_cases {
            // update state
            state.index.height = tc.height;

            // sig hash
            let sig_hash = unsigned_transaction
                .whole_sig_hash(
                    &state,
                    &Hash256::default(), // empty hash
                    1,                   // second key
                    100,
                    &Vec::new(), // no sigs
                )
                .unwrap();
            assert_eq!(sig_hash, tc.sig_hash,);

            // sign and verify
            let signature = key.sign(sig_hash.as_ref());
            assert_eq!(signature, tc.signature);
            assert!(key.public_key().verify(&sig_hash.as_ref(), &signature));
        }
    }
}
