use core::fmt;

use crate::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable, AsyncSiaEncode};
use crate::types::{Hash256, HexParseError};
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::Error;
use serde::{Deserialize, Serialize};

/// An ed25519 public key that can be used to verify a signature
#[derive(Debug, PartialEq, Clone, Copy, SiaEncode, SiaDecode, AsyncSiaDecode, AsyncSiaEncode)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    const PREFIX: &'static str = "ed25519:";
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let result = s.parse().map_err(|e| Error::custom(format!("{e:?}")))?;
        Ok(result)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = crate::types::HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(Self::PREFIX)
            .ok_or(HexParseError::MissingPrefix)?;
        let mut pk = [0; 32];
        hex::decode_to_slice(s, &mut pk)?;
        Ok(Self::new(pk))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", Self::PREFIX, hex::encode(self.0))
    }
}

impl PublicKey {
    pub const fn new(buf: [u8; 32]) -> Self {
        PublicKey(buf)
    }

    /// verifies a message against the signature using this public key
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let pk = VerifyingKey::from_bytes(&self.0).unwrap();
        pk.verify(msg, &ED25519Signature::from_bytes(signature.as_ref()))
            .is_ok()
    }
}

impl From<PublicKey> for [u8; 32] {
    fn from(val: PublicKey) -> Self {
        val.0
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

    pub fn sign(&self, h: &[u8]) -> Signature {
        let sk = SigningKey::from_bytes(&self.0[..32].try_into().unwrap());
        Signature::new(sk.sign(h).to_bytes())
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

#[derive(Debug, Clone, PartialEq, Eq, SiaEncode, SiaDecode, AsyncSiaEncode, AsyncSiaDecode)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&hex::encode(self.0), serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = hex::decode(String::deserialize(deserializer)?)
            .map_err(|e| D::Error::custom(format!("{e:?}")))?;
        if buf.len() != 64 {
            return Err(D::Error::custom("Invalid signature length"));
        }
        Ok(Signature(buf.try_into().unwrap()))
    }
}

impl Signature {
    pub const fn new(sig: [u8; 64]) -> Self {
        Signature(sig)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
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

impl From<[u8; 64]> for Signature {
    fn from(buf: [u8; 64]) -> Self {
        Signature(buf)
    }
}

impl std::str::FromStr for Signature {
    type Err = crate::types::HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = hex::decode(s).map_err(HexParseError::HexError)?;
        if data.len() != 64 {
            return Err(HexParseError::InvalidLength(data.len()));
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data);
        Ok(Signature(sig))
    }
}

/// Converts a slice of bytes into a Signature.
/// # Errors
/// Returns an error if the slice is not exactly 64 bytes long.
impl TryFrom<&[u8]> for Signature {
    type Error = encoding::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 64 {
            return Err(encoding::Error::InvalidLength(value.len()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(value);
        Ok(Signature(sig))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_publickey() {
        let public_key_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let public_key = PublicKey::new(hex::decode(public_key_str).unwrap().try_into().unwrap());

        // binary
        let mut public_key_serialized = Vec::new();
        public_key.encode(&mut public_key_serialized).unwrap();
        assert_eq!(public_key_serialized, hex::decode(public_key_str).unwrap());
        let public_key_deserialized =
            PublicKey::decode(&mut public_key_serialized.as_slice()).unwrap();
        assert_eq!(public_key_deserialized, public_key);

        // json
        let public_key_serialized = serde_json::to_string(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            serde_json::from_str(&public_key_serialized).unwrap();
        assert_eq!(
            public_key_serialized,
            format!("\"ed25519:{public_key_str}\"")
        );
        assert_eq!(public_key_deserialized, public_key);
    }
}
