use chrono::{DateTime, Duration};
use serde::Deserialize;
use sia_core_derive::cross_target_test;

use super::*;
use crate::consensus::{ElementAccumulator, Network, State};
use crate::test_util::{
    Case, Hex, Json, RawUnlockConditions, golden_cases, null_as_empty, strip_go_derived_fields,
};
use crate::types::{BlockID, ChainIndex, Work};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum V1Kind {
    UnlockConditions {
        object: RawUnlockConditions,
        binary: Hex,
        address: Address,
    },
    Transaction {
        object: Box<Json<Transaction>>,
        binary: Hex,
        id: TransactionID,
        #[serde(rename = "siacoinOutputIDs", deserialize_with = "null_as_empty")]
        siacoin_output_ids: Vec<SiacoinOutputID>,
        #[serde(rename = "siafundOutputIDs", deserialize_with = "null_as_empty")]
        siafund_output_ids: Vec<SiafundOutputID>,
        #[serde(rename = "fileContractIDs", deserialize_with = "null_as_empty")]
        file_contract_ids: Vec<FileContractID>,
        signatures: Vec<SignatureCase>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureCase {
    name: String,
    height: u64,
    #[serde(rename = "parentID")]
    parent_id: Hash256,
    public_key_index: u64,
    timelock: u64,
    covered_signatures: Vec<usize>,
    whole_sig_hash: Hash256,
    covered_fields_binary: Hex,
    partial_sig_hash: Hash256,
}

fn decode<T: V1SiaDecodable + V1SiaEncodable>(binary: &Hex, name: &str) -> T {
    let mut reader = &**binary;
    let value = T::decode_v1(&mut reader).unwrap();
    assert!(reader.is_empty(), "{name}: unread bytes");
    let mut encoded = Vec::new();
    value.encode_v1(&mut encoded).unwrap();
    assert_eq!(encoded, **binary, "{name}: binary encoding");
    value
}

fn chain_state(height: u64) -> ChainState {
    let mut network = Network::mainnet();
    network.hardfork_asic.height = 10;
    network.hardfork_foundation.height = 20;
    network.hardfork_v2.allow_height = 30;
    ChainState {
        network,
        state: State {
            index: ChainIndex {
                height,
                id: BlockID::default(),
            },
            prev_timestamps: [DateTime::UNIX_EPOCH; 11],
            depth: BlockID::default(),
            child_target: BlockID::default(),
            siafund_pool: Currency::zero(),
            oak_time: Duration::zero(),
            oak_target: BlockID::default(),
            foundation_primary_address: Address::default(),
            foundation_failsafe_address: Address::default(),
            total_work: Work::zero(),
            difficulty: Work::zero(),
            oak_work: Work::zero(),
            elements: ElementAccumulator::default(),
            attestations: 0,
        },
    }
}

#[cross_target_test]
fn go_v1_consensus_goldens() {
    for Case { name, kind } in golden_cases::<Case<V1Kind>>("v1") {
        match kind {
            V1Kind::UnlockConditions {
                object,
                binary,
                address,
            } => {
                let uc: UnlockConditions = decode(&binary, &name);
                assert_eq!(uc, object.into(), "{name}: decoded fields");
                assert_eq!(uc.address(), address, "{name}: address");
            }
            V1Kind::Transaction {
                object,
                binary,
                id,
                siacoin_output_ids,
                siafund_output_ids,
                file_contract_ids,
                signatures,
            } => {
                let txn: Transaction = decode(&binary, &name);
                let Json {
                    value: expected,
                    raw: mut expected_json,
                } = *object;
                assert_eq!(txn, expected, "{name}: decoded fields");
                strip_go_derived_fields(&mut expected_json);
                assert_eq!(
                    serde_json::to_value(&txn).unwrap(),
                    expected_json,
                    "{name}: JSON encoding"
                );
                assert_eq!(txn.id(), id, "{name}: transaction ID");

                assert_eq!(
                    siacoin_output_ids.len(),
                    txn.siacoin_outputs.len(),
                    "{name}: siacoin output count"
                );
                for (i, expected) in siacoin_output_ids.into_iter().enumerate() {
                    assert_eq!(
                        txn.siacoin_output_id(i as u64),
                        expected,
                        "{name}: siacoin output {i}"
                    );
                }
                assert_eq!(
                    siafund_output_ids.len(),
                    txn.siafund_outputs.len(),
                    "{name}: siafund output count"
                );
                for (i, expected) in siafund_output_ids.into_iter().enumerate() {
                    assert_eq!(
                        txn.siafund_output_id(i as u64),
                        expected,
                        "{name}: siafund output {i}"
                    );
                }
                assert_eq!(
                    file_contract_ids.len(),
                    txn.file_contracts.len(),
                    "{name}: file contract count"
                );
                for (i, expected) in file_contract_ids.into_iter().enumerate() {
                    assert_eq!(
                        txn.file_contract_id(i as u64),
                        expected,
                        "{name}: file contract {i}"
                    );
                }

                for sig in signatures {
                    let cs = chain_state(sig.height);
                    let hash = txn
                        .whole_sig_hash(
                            &cs,
                            &sig.parent_id,
                            sig.public_key_index,
                            sig.timelock,
                            &sig.covered_signatures,
                        )
                        .unwrap();
                    assert_eq!(
                        hash, sig.whole_sig_hash,
                        "{name}/{}: whole sig hash",
                        sig.name
                    );
                    let covered_fields: CoveredFields =
                        decode(&sig.covered_fields_binary, &sig.name);
                    assert_eq!(
                        txn.partial_sig_hash(&cs, &covered_fields).unwrap(),
                        sig.partial_sig_hash,
                        "{name}/{}: partial sig hash",
                        sig.name
                    );
                }
                assert!(
                    txn.whole_sig_hash(
                        &chain_state(0),
                        &Hash256::default(),
                        0,
                        0,
                        &[txn.signatures.len()],
                    )
                    .is_err(),
                    "{name}: invalid covered signature"
                );
            }
        }
    }
}
