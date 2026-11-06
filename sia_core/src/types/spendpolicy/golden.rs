use std::fmt::Debug;

use serde::Deserialize;
use serde_json::Value;
use sia_core_derive::cross_target_test;

use super::*;
use crate::test_util::{Case, Hex, Json, golden_cases};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum PolicyKind {
    Policy {
        object: Json<SpendPolicy>,
        binary: Hex,
        address: Address,
    },
    #[serde(rename_all = "camelCase")]
    Satisfied {
        object: Json<SatisfiedPolicy>,
        binary: Hex,
        policy_address: Address,
    },
}

/// Go marshals a nil `of` as `null`.
fn empty_thresholds(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(of) = map.get_mut("of")
                && of.is_null()
            {
                *of = Value::Array(Vec::new());
            }
            map.values_mut().for_each(empty_thresholds);
        }
        Value::Array(items) => items.iter_mut().for_each(empty_thresholds),
        _ => {}
    }
}

async fn check_binary<T>(name: &str, binary: &Hex) -> T
where
    T: SiaEncodable + SiaDecodable + AsyncSiaDecodable + PartialEq + Debug,
{
    let mut reader = &**binary;
    let value = T::decode(&mut reader).unwrap();
    assert!(reader.is_empty(), "{name}: unread bytes");
    let mut reader = &**binary;
    assert_eq!(
        T::decode_async(&mut reader).await.unwrap(),
        value,
        "{name}: async decoding"
    );
    assert!(reader.is_empty(), "{name}: unread async bytes");
    assert_eq!(
        value.encoded_length(),
        binary.len(),
        "{name}: encoded length"
    );
    let mut encoded = Vec::new();
    value.encode(&mut encoded).unwrap();
    assert_eq!(encoded, **binary, "{name}: binary encoding");
    value
}

fn check_json<T: Serialize>(name: &str, value: &T, mut expected: Value) {
    empty_thresholds(&mut expected);
    assert_eq!(
        serde_json::to_value(value).unwrap(),
        expected,
        "{name}: JSON encoding"
    );
}

#[cross_target_test]
async fn go_policy_consensus_goldens() {
    for Case { name, kind } in golden_cases::<Case<PolicyKind>>("policies") {
        match kind {
            PolicyKind::Policy {
                object,
                binary,
                address,
            } => {
                let policy: SpendPolicy = check_binary(&name, &binary).await;
                assert_eq!(policy, object.value, "{name}: decoded fields");
                check_json(&name, &policy, object.raw);
                assert_eq!(policy.address(), address, "{name}: address");
            }
            PolicyKind::Satisfied {
                object,
                binary,
                policy_address,
            } => {
                let policy: SatisfiedPolicy = check_binary(&name, &binary).await;
                assert_eq!(policy, object.value, "{name}: decoded fields");
                check_json(&name, &policy, object.raw);
                assert_eq!(policy.policy.address(), policy_address, "{name}: address");
            }
        }
    }
}
