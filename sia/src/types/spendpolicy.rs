use crate::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::signing::{PublicKey, Signature};
#[allow(deprecated)]
use crate::types::v1::UnlockConditions;
use crate::types::{Address, Hash256};
use blake2b_simd::Params;
use core::fmt;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use time::OffsetDateTime;

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
    After(OffsetDateTime),
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
    pub fn after(timestamp: OffsetDateTime) -> Self {
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
        } else if let SpendPolicy::Opaque(addr) = self {
            return addr.clone();
        }

        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/address|".as_bytes());

        if let SpendPolicy::Threshold(n, of) = self {
            let mut opaque = Vec::with_capacity(of.len());
            for policy in of {
                opaque.push(SpendPolicy::Opaque(policy.address()))
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
                        let unix_seconds: u64 =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        let timestamp = OffsetDateTime::from_unix_timestamp(unix_seconds as i64)
                            .map_err(|_| de::Error::custom("invalid timestamp"))?;
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
                            of: Vec<SpendPolicy>,
                        }
                        let thresh: ThreshPolicy =
                            serde_json::from_value(policy_value).map_err(de::Error::custom)?;
                        Ok(SpendPolicy::Threshold(thresh.n, thresh.of))
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
                let unix_seconds = time.unix_timestamp() as u64;
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
    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        // helper to recursively encode policies
        fn encode_policy<W: std::io::Write>(
            policy: &SpendPolicy,
            w: &mut W,
        ) -> encoding::Result<()> {
            w.write_all(&[policy.type_prefix()])?;
            match policy {
                SpendPolicy::Above(height) => height.encode(w),
                SpendPolicy::After(time) => (time.unix_timestamp() as u64).encode(w),
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
                    let timestamp: OffsetDateTime =
                        OffsetDateTime::from_unix_timestamp(unix_seconds as i64).map_err(|_| {
                            encoding::Error::Custom("invalid timestamp".to_string())
                        })?;
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

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
/// A policy that has been satisfied by a set of preimages and signatures.
pub struct SatisfiedPolicy {
    pub policy: SpendPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<Signature>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preimages: Vec<Hash256>,
}

#[cfg(test)]
mod tests {
    use crate::{hash_256, public_key};

    use super::*;

    #[test]
    fn test_address() {
        let test_cases = vec![
            (
                SpendPolicy::PublicKey(PublicKey::new([
                    1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])),
                "55a7793237722c6df8222fd512063cb74228085ef1805c5184713648c159b919ac792fbad0e1",
            ),
            (
                SpendPolicy::Above(100),
                "c2fba9b9607c800e80d9284ed0fb9a55737ba1bbd67311d0d9242dd6376bed0c6ee355e814fa",
            ),
            (
                SpendPolicy::After(OffsetDateTime::from_unix_timestamp(1433600000).unwrap()),
                "5bdb96e33ffdf72619ad38bee57ad4db9eb242aeb2ee32020ba16179af5d46d501bd2011806b",
            ),
            (
                SpendPolicy::Hash(Hash256::from([
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])),
                "1cc0fc4cde659333cf7e61971cc5025c5a6b4759c9d1c1d438227c3eb57d841512d4cd4ce620",
            ),
            (
                SpendPolicy::Threshold(
                    2,
                    vec![
                        SpendPolicy::PublicKey(PublicKey::new([
                            1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ])),
                        SpendPolicy::Above(100),
                        SpendPolicy::Threshold(
                            2,
                            vec![
                                SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                                SpendPolicy::After(
                                    OffsetDateTime::from_unix_timestamp(1433600000).unwrap(),
                                ),
                            ],
                        ),
                    ],
                ),
                "30f516630280059c25ae92f3bf3c451be258ecd3249c43906e3d9dd9e86f2dc00ef5eeffc2c4",
            ),
        ];

        for (policy, expected) in test_cases {
            assert_eq!(policy.address().to_string(), expected);
        }
    }

    #[test]
    fn test_opaque_policy() {
        let test_cases = vec![
            SpendPolicy::above(100),
            SpendPolicy::after(OffsetDateTime::from_unix_timestamp(100).unwrap()),
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
                            SpendPolicy::after(OffsetDateTime::from_unix_timestamp(100).unwrap()),
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
            assert_eq!(
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
    fn test_policy_encoding() {
        let test_cases = vec![
            (
                SpendPolicy::above(100),
                "{\"type\":\"above\",\"policy\":100}",
                "01016400000000000000",
            ),
            (
                SpendPolicy::after(OffsetDateTime::from_unix_timestamp(100).unwrap()),
                "{\"type\":\"after\",\"policy\":100}",
                "01026400000000000000"
            ),
            (
                SpendPolicy::public_key(PublicKey::new([1; 32])),
                "{\"type\":\"pk\",\"policy\":\"ed25519:0101010101010101010101010101010101010101010101010101010101010101\"}",
                "01030101010101010101010101010101010101010101010101010101010101010101",
            ),
            (
                SpendPolicy::hash(Hash256::from([0; 32])),
                "{\"type\":\"h\",\"policy\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
                "01040000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                SpendPolicy::threshold(
                    2,
                    vec![
                        SpendPolicy::public_key(PublicKey::new([0; 32])),
                        SpendPolicy::above(100),
                    ],
                ),
                "{\"type\":\"thresh\",\"policy\":{\"n\":2,\"of\":[{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"},{\"policy\":100,\"type\":\"above\"}]}}",
                "01050202030000000000000000000000000000000000000000000000000000000000000000016400000000000000",
            ),
            (
                SpendPolicy::threshold(
                    2,
                    vec![
                        SpendPolicy::public_key(PublicKey::new([0; 32])),
                        SpendPolicy::above(100),
                        SpendPolicy::threshold(
                            2,
                            vec![
                                SpendPolicy::public_key(PublicKey::new([0; 32])),
                                SpendPolicy::after(OffsetDateTime::from_unix_timestamp(100).unwrap()),
                            ],
                        ),
                        SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                    ],
                ),
                "{\"type\":\"thresh\",\"policy\":{\"n\":2,\"of\":[{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"},{\"policy\":100,\"type\":\"above\"},{\"policy\":{\"n\":2,\"of\":[{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"},{\"policy\":100,\"type\":\"after\"}]},\"type\":\"thresh\"},{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"}]}}",
                "01050204030000000000000000000000000000000000000000000000000000000000000000016400000000000000050202030000000000000000000000000000000000000000000000000000000000000000026400000000000000030000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                #[allow(deprecated)]
                SpendPolicy::UnlockConditions(UnlockConditions {
                    timelock: 100,
                    signatures_required: 2,
                    public_keys: vec![
                        PublicKey::new([0; 32]).into(),
                        PublicKey::new([1; 32]).into(),
                    ],
                }),
                "{\"type\":\"uc\",\"policy\":{\"timelock\":100,\"publicKeys\":[\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"ed25519:0101010101010101010101010101010101010101010101010101010101010101\"],\"signaturesRequired\":2}}",
                "010764000000000000000200000000000000656432353531390000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000065643235353139000000000000000000200000000000000001010101010101010101010101010101010101010101010101010101010101010200000000000000",
            )
        ];

        for (i, (policy, json, binary)) in test_cases.iter().enumerate() {
            let serialized_json = serde_json::to_string(&policy)
                .unwrap_or_else(|e| panic!("failed to serialize json in test case {i}: {e}"));
            assert_eq!(serialized_json, *json, "test case {i}");
            let deserialized_json: SpendPolicy = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("failed to deserialize json in test case {i}: {e}"));
            assert_eq!(deserialized_json, *policy, "test case {i}");

            let mut serialized_binary = Vec::new();
            policy
                .encode(&mut serialized_binary)
                .unwrap_or_else(|e| panic!("failed to serialize binary in test case {i}: {e}"));
            assert_eq!(
                hex::encode(serialized_binary.clone()),
                *binary,
                "test case {i}"
            );

            let deserialized_binary = SpendPolicy::decode(&mut &serialized_binary[..])
                .unwrap_or_else(|e| {
                    panic!("failed to deserialize binary in test case {i}: {e}")
                });
            assert_eq!(deserialized_binary, *policy, "test case {i}");
        }
    }

    #[test]
    fn test_satisfied_policy_encoding() {
        struct TestCase {
            policy: SatisfiedPolicy,
            json: &'static str,
            binary: &'static str,
        }
        let test_cases = vec![
        TestCase{
            policy: SatisfiedPolicy{
                policy: SpendPolicy::public_key(public_key!("ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")),
                signatures: vec![Signature::parse_string("867c405977a52caf455221d49ea6242584221ab7f6b1a3e5a7e515d1f4027852e641330366fbd93950e5d15d7153c288a7d96462db912235129725bf13b2a30c").unwrap()],
                preimages: vec![],
            },
            json: "{\"policy\":{\"type\":\"pk\",\"policy\":\"ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29\"},\"signatures\":[\"867c405977a52caf455221d49ea6242584221ab7f6b1a3e5a7e515d1f4027852e641330366fbd93950e5d15d7153c288a7d96462db912235129725bf13b2a30c\"]}",
            binary: "01033b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290100000000000000867c405977a52caf455221d49ea6242584221ab7f6b1a3e5a7e515d1f4027852e641330366fbd93950e5d15d7153c288a7d96462db912235129725bf13b2a30c0000000000000000",
        },
        TestCase{
            policy: SatisfiedPolicy{
                policy: SpendPolicy::threshold(1, vec![
                    SpendPolicy::public_key(public_key!("ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")),
                    SpendPolicy::hash(hash_256!("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")),
                ]),
                signatures: vec![Signature::parse_string("867c405977a52caf455221d49ea6242584221ab7f6b1a3e5a7e515d1f4027852e641330366fbd93950e5d15d7153c288a7d96462db912235129725bf13b2a30c").unwrap()],
                preimages: vec![hash_256!("0102030000000000000000000000000000000000000000000000000000000000")],
            },
            json: "{\"policy\":{\"type\":\"thresh\",\"policy\":{\"n\":1,\"of\":[{\"policy\":\"ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29\",\"type\":\"pk\"},{\"policy\":\"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\",\"type\":\"h\"}]}},\"signatures\":[\"867c405977a52caf455221d49ea6242584221ab7f6b1a3e5a7e515d1f4027852e641330366fbd93950e5d15d7153c288a7d96462db912235129725bf13b2a30c\"],\"preimages\":[\"0102030000000000000000000000000000000000000000000000000000000000\"]}",
            binary: "01050102033b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29040e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a80100000000000000867c405977a52caf455221d49ea6242584221ab7f6b1a3e5a7e515d1f4027852e641330366fbd93950e5d15d7153c288a7d96462db912235129725bf13b2a30c01000000000000000102030000000000000000000000000000000000000000000000000000000000",
        },
        TestCase{
            policy: SatisfiedPolicy{
                policy: SpendPolicy::hash(hash_256!("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")),
                signatures: vec![],
                preimages: vec![hash_256!("0405060000000000000000000000000000000000000000000000000000000000")],
            },
            json: "{\"policy\":{\"type\":\"h\",\"policy\":\"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\"},\"preimages\":[\"0405060000000000000000000000000000000000000000000000000000000000\"]}",
            binary: "01040e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000000000000001000000000000000405060000000000000000000000000000000000000000000000000000000000",
        },
        TestCase{
            policy: SatisfiedPolicy{
                policy: SpendPolicy::public_key(public_key!("ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")),
                signatures: vec![],
                preimages: vec![],
            },
            json: "{\"policy\":{\"type\":\"pk\",\"policy\":\"ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29\"}}",
            binary: "01033b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2900000000000000000000000000000000",
        },
        TestCase{
            policy: SatisfiedPolicy{
                policy: SpendPolicy::hash(hash_256!("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")),
                signatures: vec![],
                preimages: vec![],
            },
            json: "{\"policy\":{\"type\":\"h\",\"policy\":\"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\"}}",
            binary: "01040e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a800000000000000000000000000000000",
        }
        ];

        for tc in test_cases {
            let mut serialized = Vec::new();
            tc.policy.encode(&mut serialized).unwrap();
            assert_eq!(
                hex::encode(serialized.clone()),
                tc.binary,
                "binary serialization failed"
            );
            let deserialized = SatisfiedPolicy::decode(&mut &serialized[..]).unwrap();
            assert_eq!(deserialized, tc.policy, "binary deserialization failed");

            // json
            let serialized = serde_json::to_string(&tc.policy).unwrap();
            assert_eq!(serialized, tc.json, "json serialization failed");
            let deserialized: SatisfiedPolicy = serde_json::from_str(tc.json).unwrap();
            assert_eq!(deserialized, tc.policy, "json deserialization failed");
        }
    }
}
