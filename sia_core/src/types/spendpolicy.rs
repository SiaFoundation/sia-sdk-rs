use crate::encoding::{
    self, Error as EncodingError, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode,
};
use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode};
use crate::signing::{PublicKey, Signature};
#[allow(deprecated)]
use crate::types::v1::UnlockConditions;
use crate::types::{Address, Hash256};
use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use core::fmt;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::io::AsyncRead;

const POLICY_ABOVE_PREFIX: u8 = 1;
const POLICY_AFTER_PREFIX: u8 = 2;
const POLICY_PUBLIC_KEY_PREFIX: u8 = 3;
const POLICY_HASH_PREFIX: u8 = 4;
const POLICY_THRESHOLD_PREFIX: u8 = 5;
const POLICY_OPAQUE_PREFIX: u8 = 6;
#[deprecated]
const POLICY_UNLOCK_CONDITIONS_PREFIX: u8 = 7;

const POLICY_ABOVE_STR: &str = "above";
const POLICY_AFTER_STR: &str = "after";
const POLICY_PUBLIC_KEY_STR: &str = "pk";
const POLICY_HASH_STR: &str = "h";
const POLICY_THRESHOLD_STR: &str = "thresh";
const POLICY_OPAQUE_STR: &str = "opaque";
#[deprecated]
const POLICY_UNLOCK_CONDITIONS_STR: &str = "uc";

#[derive(Debug, PartialEq, Error)]
pub enum ValidationError {
    #[error("opaque policy")]
    OpaquePolicy,
    #[error("invalid policy")]
    InvalidPolicy,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid preimage")]
    InvalidPreimage,
    #[error("invalid height")]
    InvalidHeight,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("missing signature")]
    MissingSignature,
    #[error("missing preimage")]
    MissingPreimage,
    #[error("threshold not met")]
    ThresholdNotMet,
}

/// A spend policy is a condition or set of conditions that must be met in
/// order to spend a UTXO.
#[derive(Debug, PartialEq, Clone)]
pub enum SpendPolicy {
    /// A policy that is only valid after a block height
    Above(u64),
    /// A policy that is only valid after a timestamp
    After(DateTime<Utc>),
    /// A policy that requires a valid signature from an ed25519 key pair
    PublicKey(PublicKey),
    /// A policy that requires a valid SHA256 hash preimage
    Hash(Hash256),
    /// A threshold policy that requires n-of-m sub-policies to be met
    Threshold(u8, Vec<SpendPolicy>),
    /// An opaque policy that is not directly spendable
    Opaque(Address),

    /// A set of v1 unlock conditions for compatibility with v1 transactions
    #[deprecated]
    UnlockConditions(UnlockConditions),
}

impl SpendPolicy {
    fn type_prefix(&self) -> u8 {
        match self {
            SpendPolicy::Above(_) => POLICY_ABOVE_PREFIX,
            SpendPolicy::After(_) => POLICY_AFTER_PREFIX,
            SpendPolicy::PublicKey(_) => POLICY_PUBLIC_KEY_PREFIX,
            SpendPolicy::Hash(_) => POLICY_HASH_PREFIX,
            SpendPolicy::Threshold(_, _) => POLICY_THRESHOLD_PREFIX,
            SpendPolicy::Opaque(_) => POLICY_OPAQUE_PREFIX,
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(_) => POLICY_UNLOCK_CONDITIONS_PREFIX,
        }
    }

    fn type_str(&self) -> &str {
        match self {
            SpendPolicy::Above(_) => POLICY_ABOVE_STR,
            SpendPolicy::After(_) => POLICY_AFTER_STR,
            SpendPolicy::PublicKey(_) => POLICY_PUBLIC_KEY_STR,
            SpendPolicy::Hash(_) => POLICY_HASH_STR,
            SpendPolicy::Threshold(_, _) => POLICY_THRESHOLD_STR,
            SpendPolicy::Opaque(_) => POLICY_OPAQUE_STR,
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(_) => POLICY_UNLOCK_CONDITIONS_STR,
        }
    }

    /// Create a policy that is only valid after a certain block height
    pub fn above(height: u64) -> Self {
        Self::Above(height)
    }

    /// Create a policy that is only valid after a certain timestamp
    pub fn after(timestamp: DateTime<Utc>) -> Self {
        Self::After(timestamp)
    }

    /// Create a policy that requires a valid signature from a public key
    pub fn public_key(pk: PublicKey) -> Self {
        Self::PublicKey(pk)
    }

    /// Create a policy that requires a hash preimage
    pub fn hash(hash: Hash256) -> Self {
        Self::Hash(hash)
    }

    /// Create a threshold policy with n-of-m sub-policies
    pub fn threshold(n: u8, policies: Vec<SpendPolicy>) -> Self {
        for policy in policies.iter() {
            #[allow(deprecated)]
            if let SpendPolicy::UnlockConditions(_) = policy {
                panic!("UnlockConditions are not allowed in a threshold policy");
            }
        }
        Self::Threshold(n, policies)
    }

    /// Create a v1 unlock conditions policy for compatibility with v1
    /// transactions.
    #[deprecated]
    pub fn unlock_conditions(uc: UnlockConditions) -> Self {
        #[allow(deprecated)]
        Self::UnlockConditions(uc)
    }

    /// Returns the address of the policy. This is a hash of the policy that
    /// can be used to receive funds.
    pub fn address(&self) -> Address {
        #[allow(deprecated)]
        if let SpendPolicy::UnlockConditions(uc) = self {
            return uc.address();
        }

        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/address|".as_bytes());

        if let SpendPolicy::Threshold(n, of) = self {
            let mut opaque = Vec::with_capacity(of.len());
            for policy in of {
                opaque.push(match policy {
                    SpendPolicy::Opaque(_) => policy.clone(),
                    _ => SpendPolicy::Opaque(policy.address()),
                })
            }
            SpendPolicy::Threshold(*n, opaque)
                .encode(&mut state)
                .unwrap();
        } else {
            self.encode(&mut state).unwrap();
        }
        Address::from(state.finalize().as_bytes())
    }
}

impl<'de> Deserialize<'de> for SpendPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SpendPolicyVisitor;

        impl<'de> Visitor<'de> for SpendPolicyVisitor {
            type Value = SpendPolicy;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a spend policy")
            }

            // json encoding
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut policy_type: Option<String> = None;
                let mut policy_value: Option<serde_json::Value> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            policy_type = Some(map.next_value()?);
                        }
                        "policy" => {
                            policy_value = Some(map.next_value()?);
                        }
                        _ => return Err(de::Error::unknown_field(&key, &["type", "policy"])),
                    }
                }

                let policy_type = policy_type.ok_or_else(|| de::Error::missing_field("type"))?;
                let policy_value =
                    policy_value.ok_or_else(|| de::Error::missing_field("policy"))?;

                match policy_type.as_str() {
                    POLICY_ABOVE_STR => {
                        let height =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        Ok(SpendPolicy::Above(height))
                    }
                    POLICY_AFTER_STR => {
                        let unix_seconds: i64 =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        let timestamp = DateTime::from_timestamp_secs(unix_seconds)
                            .ok_or(de::Error::custom("invalid timestamp"))?;
                        Ok(SpendPolicy::After(timestamp))
                    }
                    POLICY_PUBLIC_KEY_STR => {
                        let pk: PublicKey =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        Ok(SpendPolicy::PublicKey(pk))
                    }
                    POLICY_HASH_STR => {
                        let hash: Hash256 =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        Ok(SpendPolicy::Hash(hash))
                    }
                    POLICY_THRESHOLD_STR => {
                        #[derive(Deserialize)]
                        struct ThreshPolicy {
                            n: u8,
                            of: Option<Vec<SpendPolicy>>,
                        }
                        let thresh: ThreshPolicy =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        Ok(SpendPolicy::Threshold(
                            thresh.n,
                            thresh.of.unwrap_or_default(),
                        ))
                    }
                    POLICY_OPAQUE_STR => {
                        let addr: Address =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        Ok(SpendPolicy::Opaque(addr))
                    }
                    #[allow(deprecated)]
                    POLICY_UNLOCK_CONDITIONS_STR => {
                        #[allow(deprecated)]
                        let uc: UnlockConditions =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        #[allow(deprecated)]
                        Ok(SpendPolicy::UnlockConditions(uc))
                    }
                    _ => Err(de::Error::unknown_variant(
                        &policy_type,
                        #[allow(deprecated)]
                        &[
                            POLICY_ABOVE_STR,
                            POLICY_AFTER_STR,
                            POLICY_PUBLIC_KEY_STR,
                            POLICY_HASH_STR,
                            POLICY_THRESHOLD_STR,
                            POLICY_OPAQUE_STR,
                            POLICY_UNLOCK_CONDITIONS_STR,
                        ],
                    )),
                }
            }
        }

        deserializer.deserialize_map(SpendPolicyVisitor)
    }
}

impl Serialize for SpendPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SpendPolicy", 2)?;
        state.serialize_field("type", self.type_str())?;
        match self {
            SpendPolicy::Above(height) => {
                state.serialize_field("policy", height)?;
            }
            SpendPolicy::After(time) => {
                let unix_seconds = time.timestamp();
                state.serialize_field("policy", &unix_seconds)?;
            }
            SpendPolicy::PublicKey(pk) => {
                state.serialize_field("policy", &pk)?;
            }
            SpendPolicy::Hash(hash) => {
                state.serialize_field("policy", &hash)?;
            }
            SpendPolicy::Threshold(n, policies) => {
                state.serialize_field(
                    "policy",
                    &json!({
                        "n": n,
                        "of": policies,
                    }),
                )?;
            }
            SpendPolicy::Opaque(addr) => {
                state.serialize_field("policy", addr)?;
            }
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => {
                state.serialize_field("policy", uc)?;
            }
        }
        state.end()
    }
}

impl SiaEncodable for SpendPolicy {
    fn encoded_length(&self) -> usize {
        fn policy_length(policy: &SpendPolicy) -> usize {
            1 + match policy {
                // 1 byte type prefix
                SpendPolicy::Above(_) => 8,
                SpendPolicy::After(dt) => dt.encoded_length(),
                SpendPolicy::PublicKey(pk) => pk.encoded_length(),
                SpendPolicy::Hash(hash) => hash.encoded_length(),
                SpendPolicy::Threshold(_, policies) => {
                    1 + 1 + policies.iter().map(policy_length).sum::<usize>() // of + count + policies
                }
                SpendPolicy::Opaque(addr) => addr.encoded_length(),
                #[allow(deprecated)]
                SpendPolicy::UnlockConditions(uc) => uc.encoded_length(),
            }
        }
        1 + policy_length(self) // version byte + policy
    }

    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        // helper to recursively encode policies
        fn encode_policy<W: std::io::Write>(
            policy: &SpendPolicy,
            w: &mut W,
        ) -> encoding::Result<()> {
            w.write_all(&[policy.type_prefix()])?;
            match policy {
                SpendPolicy::Above(height) => height.encode(w),
                SpendPolicy::After(time) => (time.timestamp() as u64).encode(w),
                SpendPolicy::PublicKey(pk) => pk.encode(w),
                SpendPolicy::Hash(hash) => hash.encode(w),
                SpendPolicy::Threshold(of, policies) => {
                    of.encode(w)?;
                    (policies.len() as u8).encode(w)?;
                    for policy in policies {
                        encode_policy(policy, w)?;
                    }
                    Ok(())
                }
                SpendPolicy::Opaque(addr) => addr.encode(w),
                #[allow(deprecated)]
                SpendPolicy::UnlockConditions(uc) => uc.encode(w),
            }
        }
        1u8.encode(w)?;
        encode_policy(self, w)
    }
}

impl SiaDecodable for SpendPolicy {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        // helper to recursively decode policies
        fn decode_policy<R: std::io::Read>(r: &mut R) -> encoding::Result<SpendPolicy> {
            let policy_type = u8::decode(r)?;
            match policy_type {
                POLICY_ABOVE_PREFIX => Ok(SpendPolicy::Above(u64::decode(r)?)),
                POLICY_AFTER_PREFIX => {
                    let unix_seconds = u64::decode(r)?;
                    let timestamp = DateTime::from_timestamp_secs(unix_seconds as i64)
                        .ok_or(EncodingError::Custom("invalid timestamp".to_string()))?;
                    Ok(SpendPolicy::After(timestamp))
                }
                POLICY_PUBLIC_KEY_PREFIX => Ok(SpendPolicy::PublicKey(PublicKey::decode(r)?)),
                POLICY_HASH_PREFIX => Ok(SpendPolicy::Hash(Hash256::decode(r)?)),
                POLICY_THRESHOLD_PREFIX => {
                    let of: u8 = u8::decode(r)?;
                    let n = u8::decode(r)?;
                    let mut policies = Vec::with_capacity(n as usize);
                    while policies.len() < n as usize {
                        policies.push(decode_policy(r)?);
                    }
                    Ok(SpendPolicy::Threshold(of, policies))
                }
                POLICY_OPAQUE_PREFIX => Ok(SpendPolicy::Opaque(Address::decode(r)?)),
                #[allow(deprecated)]
                POLICY_UNLOCK_CONDITIONS_PREFIX => {
                    Ok(SpendPolicy::UnlockConditions(UnlockConditions::decode(r)?))
                }
                _ => Err(encoding::Error::Custom("invalid policy type".to_string())),
            }
        }
        let policy_version = u8::decode(r)?;
        if policy_version != 1 {
            return Err(encoding::Error::Custom(
                "invalid policy version".to_string(),
            ));
        }
        decode_policy(r)
    }
}

impl AsyncSiaDecodable for SpendPolicy {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, EncodingError> {
        // helper to recursively decode policies, boxed to allow recursion
        fn decode_policy<'a, R: AsyncRead + Unpin>(
            r: &'a mut R,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<SpendPolicy, EncodingError>> + 'a>,
        > {
            Box::pin(async move {
                let policy_type = u8::decode_async(r).await?;
                match policy_type {
                    POLICY_ABOVE_PREFIX => Ok(SpendPolicy::Above(u64::decode_async(r).await?)),
                    POLICY_AFTER_PREFIX => {
                        Ok(SpendPolicy::After(DateTime::<Utc>::decode_async(r).await?))
                    }
                    POLICY_PUBLIC_KEY_PREFIX => {
                        Ok(SpendPolicy::PublicKey(PublicKey::decode_async(r).await?))
                    }
                    POLICY_HASH_PREFIX => Ok(SpendPolicy::Hash(Hash256::decode_async(r).await?)),
                    POLICY_THRESHOLD_PREFIX => {
                        let of: u8 = u8::decode_async(r).await?;
                        let n = u8::decode_async(r).await?;
                        let mut policies = Vec::with_capacity(n as usize);
                        while policies.len() < n as usize {
                            policies.push(decode_policy(r).await?);
                        }
                        Ok(SpendPolicy::Threshold(of, policies))
                    }
                    POLICY_OPAQUE_PREFIX => {
                        Ok(SpendPolicy::Opaque(Address::decode_async(r).await?))
                    }
                    #[allow(deprecated)]
                    POLICY_UNLOCK_CONDITIONS_PREFIX => Ok(SpendPolicy::UnlockConditions(
                        UnlockConditions::decode_async(r).await?,
                    )),
                    _ => Err(EncodingError::InvalidValue(format!(
                        "invalid policy type: {policy_type}"
                    ))),
                }
            })
        }
        let policy_version = u8::decode_async(r).await?;
        if policy_version != 1 {
            return Err(EncodingError::InvalidValue(format!(
                "invalid policy version: {policy_version}"
            )));
        }
        decode_policy(r).await
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode, Clone)]
/// A policy that has been satisfied by a set of preimages and signatures.
pub struct SatisfiedPolicy {
    pub policy: SpendPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Signature>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preimages: Vec<Hash256>,
}

#[cfg(test)]
mod golden;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_policy() {
        let test_cases = vec![
            SpendPolicy::above(100),
            SpendPolicy::after(DateTime::from_timestamp_secs(100).unwrap()),
            SpendPolicy::public_key(PublicKey::new([0; 32])),
            SpendPolicy::hash(Hash256::from([0; 32])),
            SpendPolicy::threshold(
                2,
                vec![
                    SpendPolicy::public_key(PublicKey::new([0; 32])),
                    SpendPolicy::above(100),
                ],
            ),
            SpendPolicy::threshold(
                2,
                vec![
                    SpendPolicy::public_key(PublicKey::new([0; 32])),
                    SpendPolicy::above(100),
                    SpendPolicy::threshold(
                        2,
                        vec![
                            SpendPolicy::public_key(PublicKey::new([0; 32])),
                            SpendPolicy::after(DateTime::from_timestamp_secs(100).unwrap()),
                        ],
                    ),
                    SpendPolicy::PublicKey(PublicKey::new([1; 32])),
                ],
            ),
        ];

        for (i, policy) in test_cases.into_iter().enumerate() {
            let policy = policy.clone();
            let address = policy.address();
            let expected_address = address.to_string();
            let opaque = SpendPolicy::Opaque(address);
            assert_ne!(
                opaque.address().to_string(),
                expected_address,
                "test case {i}"
            );

            if let SpendPolicy::Threshold(n, of) = policy {
                // test that the address of opaque threshold policies is the
                // same as the address of normal threshold policies
                for j in 0..of.len() {
                    let mut of = of.clone();
                    of[j] = SpendPolicy::Opaque(of[j].address());
                    let opaque_policy = SpendPolicy::threshold(n, of);

                    assert_eq!(
                        opaque_policy.address().to_string(),
                        expected_address,
                        "test case {i}-{j}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_empty_threshold_json() {
        for json in [
            r#"{"type":"thresh","policy":{"n":0,"of":null}}"#,
            r#"{"type":"thresh","policy":{"n":0,"of":[]}}"#,
            r#"{"type":"thresh","policy":{"n":0}}"#,
        ] {
            let policy: SpendPolicy = serde_json::from_str(json).unwrap();
            assert_eq!(policy, SpendPolicy::threshold(0, vec![]));
        }
    }
}
