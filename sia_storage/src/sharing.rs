use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::{DefaultOnNull, serde_as};
use sia_core::blake2::{Blake2b256, Digest};
use sia_core::encoding::SiaEncodable;
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::Hash256;

use crate::AppKey;
use crate::object_encryption::derive;
use crate::slabs::Object;

/// The size of a sharing key [`Nonce`].
pub const NONCE_SIZE: usize = 32;

/// The per-key salt used to derive a sharing key from the owner's app key. It
/// (de)serializes as a hex string, matching indexd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Nonce(pub(crate) [u8; NONCE_SIZE]);

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Nonce {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; NONCE_SIZE];
        hex::decode_to_slice(&s, &mut out)
            .map_err(|e| serde::de::Error::custom(format!("invalid nonce: {e}")))?;
        Ok(Nonce(out))
    }
}

/// Deterministically derives the sharing key's seed from the owner's app key
/// and a nonce, matching indexd's `DeriveSharingKey`. The seed is the
/// recipient's whole credential.
pub(crate) fn derive_sharing_seed(app_key: &PrivateKey, nonce: &Nonce) -> [u8; 32] {
    let mut seed = [0u8; 32];
    derive(app_key.as_ref(), &nonce.0, b"share key", &mut seed);
    seed
}

/// The body of a request to create a sharing key. It is signed by the sharing
/// key to prove control of its private half.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRequest {
    pub public_key: PublicKey,
    pub signature: Signature,
    pub nonce: Nonce,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl KeyRequest {
    /// Builds and signs a create-sharing-key request for the given key.
    pub(crate) fn new(
        sharing_key: &PrivateKey,
        nonce: Nonce,
        description: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let public_key = sharing_key.public_key();
        let sig_hash = key_request_sig_hash(&public_key, &nonce, &description, expires_at.as_ref());
        Self {
            public_key,
            signature: sharing_key.sign(sig_hash.as_ref()),
            nonce,
            description,
            expires_at,
        }
    }
}

/// The domain-separated hash signed when creating a sharing key. Mirrors
/// indexd's `KeyRequest.SigHash` byte for byte.
fn key_request_sig_hash(
    public_key: &PublicKey,
    nonce: &Nonce,
    description: &str,
    expires_at: Option<&DateTime<Utc>>,
) -> Hash256 {
    let mut state = Blake2b256::default();
    // length-prefixed strings, raw fixed-size keys/nonce, unix-seconds time
    "indexd/sharing-key/create/v1"
        .to_string()
        .encode(&mut state)
        .unwrap();
    public_key.encode(&mut state).unwrap();
    state.update(nonce.0);
    description.to_string().encode(&mut state).unwrap();
    expires_at.is_some().encode(&mut state).unwrap();
    if let Some(expires_at) = expires_at {
        expires_at.encode(&mut state).unwrap();
    }
    state.finalize().into()
}

/// The body of a request to attach an object to a sharing key. The object's
/// encryption keys are re-sealed under the sharing key so the recipient can
/// decrypt and verify them.
#[serde_as]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedObjectRequest {
    #[serde(rename = "objectID")]
    pub object_id: Hash256,
    #[serde_as(as = "Base64")]
    pub encrypted_data_key: Vec<u8>,
    pub data_signature: Signature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "DefaultOnNull<Base64>")]
    pub encrypted_metadata_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "DefaultOnNull<Base64>")]
    pub encrypted_metadata: Vec<u8>,
    pub metadata_signature: Signature,
}

impl SharedObjectRequest {
    /// Re-seals `object` under `sharing_key` so a recipient holding that key can
    /// decrypt it.
    pub(crate) fn new(object: &Object, sharing_key: &PrivateKey) -> Self {
        let sealed = object.seal(&AppKey(sharing_key.clone()));
        Self {
            object_id: object.id(),
            encrypted_data_key: sealed.encrypted_data_key,
            data_signature: sealed.data_signature,
            encrypted_metadata_key: sealed.encrypted_metadata_key,
            encrypted_metadata: sealed.encrypted_metadata,
            metadata_signature: sealed.metadata_signature,
        }
    }
}

/// A sharing key, granting read-only access to the objects attached to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingKey {
    /// The key's public half. Recipients are identified by it.
    pub public_key: PublicKey,
    pub(crate) nonce: Nonce,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors generated from indexd's Go `sharing` package (HKDF +
    // KeyRequest.SigHash) for app key seed [1;32], nonce [2;32],
    // description "photos", expiry unix 1893456000.
    #[test]
    fn test_derive_and_sig_hash_golden() {
        let app_key = PrivateKey::from_seed(&[1u8; 32]);
        let nonce = Nonce([2u8; 32]);

        let seed = derive_sharing_seed(&app_key, &nonce);
        assert_eq!(
            hex::encode(seed),
            "a4175b19800301a44ae89269d95b4bde7b68a964a150e1b4888d3b639237f0a0",
        );

        let sharing_key = PrivateKey::from_seed(&seed);
        assert_eq!(
            sharing_key.public_key().to_string(),
            "ed25519:e225d520cb027055aa6ee1b870edfd290758964b25915cc78d9da7d24e036c6b",
        );

        let expires_at = DateTime::from_timestamp(1893456000, 0);
        let sig_hash = key_request_sig_hash(
            &sharing_key.public_key(),
            &nonce,
            "photos",
            expires_at.as_ref(),
        );
        assert_eq!(
            sig_hash.to_string(),
            "49bdc0b8aab2919a5a58a74d3f6d5f151c7d16ac1742a4e4133ad6834f071238",
        );

        // the request signs the same hash and verifies against the public key
        let req = KeyRequest::new(&sharing_key, nonce, "photos".into(), expires_at);
        assert!(req.public_key.verify(sig_hash.as_ref(), &req.signature));
    }

    #[test]
    fn test_nonce_hex_roundtrip() {
        let nonce = Nonce([2u8; 32]);
        let json = serde_json::to_string(&nonce).unwrap();
        assert_eq!(json, format!("\"{}\"", "02".repeat(32)));
        assert_eq!(serde_json::from_str::<Nonce>(&json).unwrap(), nonce);
    }
}
