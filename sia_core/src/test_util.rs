//! Deterministic helpers shared across the crate's unit tests.

use std::collections::HashMap;
use std::io::Read;
use std::ops::Deref;

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde::de::{self, DeserializeOwned, Deserializer};
use serde_json::Value;

use crate::types::Specifier;
use crate::types::v1::{UnlockConditions, UnlockKey};

/// A fixture case: its name and the kind-specific fields.
#[derive(Deserialize)]
pub(crate) struct Case<K> {
    pub name: String,
    #[serde(flatten)]
    pub kind: K,
}

/// Hex-encoded bytes.
#[derive(Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Hex(Vec<u8>);

impl TryFrom<String> for Hex {
    type Error = hex::FromHexError;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        hex::decode(encoded).map(Hex)
    }
}

impl Deref for Hex {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// A Go-marshaled object and its decoded Rust value.
pub(crate) struct Json<T> {
    pub value: T,
    pub raw: Value,
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Json<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Value::deserialize(deserializer)?;
        let value = serde_json::from_value(raw.clone()).map_err(de::Error::custom)?;
        Ok(Json { value, raw })
    }
}

pub(crate) fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// Unlock conditions as the generator emits them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawUnlockConditions {
    timelock: u64,
    public_keys: Vec<RawUnlockKey>,
    signatures_required: u64,
}

#[derive(Deserialize)]
struct RawUnlockKey {
    algorithm: Hex,
    key: Hex,
}

impl From<RawUnlockConditions> for UnlockConditions {
    fn from(raw: RawUnlockConditions) -> Self {
        UnlockConditions {
            timelock: raw.timelock,
            signatures_required: raw.signatures_required,
            public_keys: raw
                .public_keys
                .into_iter()
                .map(|key| UnlockKey {
                    algorithm: Specifier::new(key.algorithm.0.try_into().unwrap()),
                    key: key.key.0,
                })
                .collect(),
        }
    }
}

/// Removes the fields Go adds when marshaling a transaction: its ID, its
/// output IDs, and the addresses of V1 inputs.
pub(crate) fn strip_go_derived_fields(object: &mut Value) {
    let Some(txn) = object.as_object_mut() else {
        return;
    };
    txn.remove("id");
    for key in ["siacoinOutputs", "siafundOutputs"] {
        let empty = match txn.get_mut(key).and_then(Value::as_array_mut) {
            Some(outputs) => {
                for output in outputs.iter_mut() {
                    if let Some(output) = output.as_object_mut() {
                        output.remove("id");
                    }
                }
                outputs.is_empty()
            }
            None => false,
        };
        if empty {
            txn.remove(key);
        }
    }
    for key in ["siacoinInputs", "siafundInputs"] {
        if let Some(inputs) = txn.get_mut(key).and_then(Value::as_array_mut) {
            for input in inputs.iter_mut() {
                if let Some(input) = input.as_object_mut() {
                    input.remove("address");
                }
            }
        }
    }
}

pub(crate) fn golden_cases<T: DeserializeOwned>(group: &str) -> Vec<T> {
    let mut json = Vec::new();
    GzDecoder::new(include_bytes!("../testdata/consensus.json.gz").as_slice())
        .read_to_end(&mut json)
        .unwrap();
    let mut groups: HashMap<String, Value> = serde_json::from_slice(&json).unwrap();
    let group_value = groups.remove(group).expect("missing golden group");
    let cases: Vec<T> = serde_json::from_value(group_value).unwrap();
    assert!(!cases.is_empty(), "empty golden group: {group}");
    cases
}

/// Fills `buf` with a deterministic splitmix64 stream seeded by `seed`.
pub(crate) fn fill(seed: u64, buf: &mut [u8]) {
    let mut x = seed.wrapping_add(0x9e3779b97f4a7c15);
    for chunk in buf.chunks_mut(8) {
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
        x = x.wrapping_add(0x9e3779b97f4a7c15);
    }
}
