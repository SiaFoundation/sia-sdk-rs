use std::fmt::Debug;

use chrono::{DateTime, Duration};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::*;
use crate::consensus::{ElementAccumulator, Network, State};
use crate::test_util::{Case, Hex, Json, golden_cases, strip_go_derived_fields};
use crate::types::{
    AttestationID, FileContractID, SiacoinOutputID, SiafundOutputID, TransactionID, Work,
};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum V2Kind {
    Transaction {
        object: Box<Json<Transaction>>,
        wire: Hex,
        hashes: TransactionHashes,
        output_ids: OutputIds,
    },
    FileContract {
        object: Box<Json<FileContract>>,
        wire: Hex,
        hashes: SigHash,
        tax: Currency,
    },
    Renewal {
        object: Box<Json<FileContractRenewal>>,
        wire: Hex,
        hashes: SigHash,
    },
    Attestation {
        object: Box<Json<Attestation>>,
        wire: Hex,
        hashes: SigHash,
    },
}

#[derive(Deserialize)]
struct TransactionHashes {
    id: TransactionID,
    input_sig_hash: Hash256,
}

#[derive(Deserialize)]
struct SigHash {
    signature_hash: Hash256,
}

#[derive(Deserialize)]
struct OutputIds {
    siacoin: Vec<SiacoinOutputID>,
    siafund: Vec<SiafundOutputID>,
    file_contract: Vec<FileContractID>,
    attestation: Vec<AttestationID>,
}

fn chain_state(height: u64) -> ChainState {
    ChainState {
        network: Network::mainnet(),
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

fn signature_heights(cs: &ChainState) -> [u64; 8] {
    [
        0,
        cs.network.hardfork_asic.height - 1,
        cs.network.hardfork_asic.height,
        cs.network.hardfork_foundation.height - 1,
        cs.network.hardfork_foundation.height,
        cs.network.hardfork_v2.allow_height - 1,
        cs.network.hardfork_v2.allow_height,
        cs.network.hardfork_v2.require_height,
    ]
}

async fn check_wire<T>(name: &str, object: Json<T>, wire: &Hex) -> T
where
    T: Serialize
        + DeserializeOwned
        + SiaEncodable
        + SiaDecodable
        + AsyncSiaDecodable
        + PartialEq
        + Debug,
{
    let Json { value, mut raw } = object;
    strip_go_derived_fields(&mut raw);
    assert_eq!(
        serde_json::to_value(&value).unwrap(),
        raw,
        "{name}: JSON encoding"
    );

    let mut actual = Vec::new();
    value.encode(&mut actual).unwrap();
    assert_eq!(actual, **wire, "{name}: Go wire encoding");
    assert_eq!(value.encoded_length(), wire.len(), "{name}: encoded length");

    let mut reader = &**wire;
    assert_eq!(
        T::decode(&mut reader).unwrap(),
        value,
        "{name}: sync decode"
    );
    assert!(reader.is_empty(), "{name}: sync decoder left bytes");
    let mut reader = &**wire;
    assert_eq!(
        T::decode_async(&mut reader).await.unwrap(),
        value,
        "{name}: async decode"
    );
    assert!(reader.is_empty(), "{name}: async decoder left bytes");
    value
}

#[sia_core_derive::cross_target_test]
async fn test_go_v2_goldens() {
    let mut cs = chain_state(0);
    for Case { name, kind } in golden_cases::<Case<V2Kind>>("v2") {
        match kind {
            V2Kind::Transaction {
                object,
                wire,
                hashes,
                output_ids,
            } => {
                let txn = check_wire(&name, *object, &wire).await;
                let id = txn.id();
                assert_eq!(id, hashes.id, "{name}: transaction ID");
                for height in signature_heights(&cs) {
                    cs.state.index.height = height;
                    assert_eq!(
                        txn.input_sig_hash(&cs),
                        hashes.input_sig_hash,
                        "{name}: input signature hash at height {height}"
                    );
                }
                assert_eq!(
                    output_ids.siacoin.len(),
                    txn.siacoin_outputs.len(),
                    "{name}: siacoin count"
                );
                for (i, expected) in output_ids.siacoin.into_iter().enumerate() {
                    assert_eq!(
                        id.v2_siacoin_output_id(i as u64),
                        expected,
                        "{name}: siacoin output {i}"
                    );
                }
                assert_eq!(
                    output_ids.siafund.len(),
                    txn.siafund_outputs.len(),
                    "{name}: siafund count"
                );
                for (i, expected) in output_ids.siafund.into_iter().enumerate() {
                    assert_eq!(
                        id.v2_siafund_output_id(i as u64),
                        expected,
                        "{name}: siafund output {i}"
                    );
                }
                assert_eq!(
                    output_ids.file_contract.len(),
                    txn.file_contracts.len(),
                    "{name}: file contract count"
                );
                for (i, expected) in output_ids.file_contract.into_iter().enumerate() {
                    assert_eq!(
                        id.v2_file_contract_id(i as u64),
                        expected,
                        "{name}: file contract {i}"
                    );
                }
                assert_eq!(
                    output_ids.attestation.len(),
                    txn.attestations.len(),
                    "{name}: attestation count"
                );
                for (i, expected) in output_ids.attestation.into_iter().enumerate() {
                    assert_eq!(
                        id.v2_attestation_id(i as u64),
                        expected,
                        "{name}: attestation {i}"
                    );
                }
            }
            V2Kind::FileContract {
                object,
                wire,
                hashes,
                tax,
            } => {
                let contract = check_wire(&name, *object, &wire).await;
                for height in signature_heights(&cs) {
                    cs.state.index.height = height;
                    assert_eq!(
                        contract.sig_hash(&cs),
                        hashes.signature_hash,
                        "{name}: signature at {height}"
                    );
                    assert_eq!(contract.tax(&cs), tax, "{name}: tax at {height}");
                }
            }
            V2Kind::Renewal {
                object,
                wire,
                hashes,
            } => {
                let renewal = check_wire(&name, *object, &wire).await;
                for height in signature_heights(&cs) {
                    cs.state.index.height = height;
                    assert_eq!(
                        renewal.sig_hash(&cs),
                        hashes.signature_hash,
                        "{name}: signature at {height}"
                    );
                }
            }
            V2Kind::Attestation {
                object,
                wire,
                hashes,
            } => {
                let attestation = check_wire(&name, *object, &wire).await;
                for height in signature_heights(&cs) {
                    cs.state.index.height = height;
                    assert_eq!(
                        attestation.sig_hash(&cs),
                        hashes.signature_hash,
                        "{name}: signature at {height}"
                    );
                }
            }
        }
    }
}

#[sia_core_derive::cross_target_test]
async fn test_signed_consensus_durations() {
    for nanoseconds in [i64::MIN, -600_000_000_000, -1, 0, 1, i64::MAX] {
        let duration = Duration::nanoseconds(nanoseconds);
        let expected = nanoseconds.to_le_bytes();
        let mut encoded = Vec::new();
        duration.encode(&mut encoded).unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(duration.encoded_length(), expected.len());
        assert_eq!(
            Duration::decode(&mut expected.as_slice()).unwrap(),
            duration
        );
        assert_eq!(
            Duration::decode_async(&mut expected.as_slice())
                .await
                .unwrap(),
            duration
        );

        let mut cs = chain_state(11);
        cs.state.oak_time = duration;
        let mut encoded = Vec::new();
        cs.state.encode(&mut encoded).unwrap();
        assert_eq!(cs.state.encoded_length(), encoded.len());
        assert_eq!(State::decode(&mut encoded.as_slice()).unwrap(), cs.state);
    }
}

#[sia_core_derive::cross_target_test]
fn test_network_v2_activation_prefixes() {
    for network in golden_cases::<Network>("networks") {
        let allow_height = network.hardfork_v2.allow_height;
        let mut cs = chain_state(allow_height - 1);
        cs.network = network;
        assert_eq!(cs.replay_prefix(), &[1]);
        assert_eq!(cs.v2_replay_prefix(), &[2]);
        cs.state.index.height = allow_height;
        assert_eq!(cs.replay_prefix(), &[2]);
        assert_eq!(cs.v2_replay_prefix(), &[2]);
    }
}

#[sia_core_derive::cross_target_test]
fn test_network_nonce_factors() {
    for network in golden_cases::<Network>("networks") {
        let height = network.hardfork_asic.height;
        let factor = network.hardfork_asic.nonce_factor;
        let mut cs = chain_state(height - 2);
        cs.network = network;
        assert_eq!(cs.nonce_factor(), 1);
        cs.state.index.height = height - 1;
        assert_eq!(cs.nonce_factor(), factor);
        cs.state.index.height = height;
        assert_eq!(cs.nonce_factor(), factor);
        cs.network.hardfork_asic.nonce_factor = 123;
        assert_eq!(cs.nonce_factor(), 123);
    }
}
