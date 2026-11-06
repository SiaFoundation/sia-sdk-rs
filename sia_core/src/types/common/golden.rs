use serde::Deserialize;

use super::*;
use crate::test_util::{Case, Hex, golden_cases};
use crate::types::v2;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum IdKind {
    Block {
        id: BlockID,
        index: u64,
        #[serde(rename = "minerOutputID")]
        miner_output_id: SiacoinOutputID,
        #[serde(rename = "foundationOutputID")]
        foundation_output_id: SiacoinOutputID,
    },
    Contract {
        id: FileContractID,
        index: u64,
        #[serde(rename = "validOutputID")]
        valid_output_id: SiacoinOutputID,
        #[serde(rename = "missedOutputID")]
        missed_output_id: SiacoinOutputID,
        #[serde(rename = "renterOutputID")]
        renter_output_id: SiacoinOutputID,
        #[serde(rename = "hostOutputID")]
        host_output_id: SiacoinOutputID,
        #[serde(rename = "renewalID")]
        renewal_id: FileContractID,
    },
    Siafund {
        id: SiafundOutputID,
        #[serde(rename = "claimOutputID")]
        claim_output_id: SiacoinOutputID,
        #[serde(rename = "v2ClaimOutputID")]
        v2_claim_output_id: SiacoinOutputID,
    },
    Transaction {
        binary: Hex,
        id: TransactionID,
        index: u64,
        #[serde(rename = "siacoinOutputID")]
        siacoin_output_id: SiacoinOutputID,
        #[serde(rename = "siafundOutputID")]
        siafund_output_id: SiafundOutputID,
        #[serde(rename = "fileContractID")]
        file_contract_id: FileContractID,
        #[serde(rename = "attestationID")]
        attestation_id: AttestationID,
    },
}

#[sia_core_derive::cross_target_test]
fn go_consensus_id_goldens() {
    for Case { name, kind } in golden_cases::<Case<IdKind>>("ids") {
        match kind {
            IdKind::Block {
                id,
                index,
                miner_output_id,
                foundation_output_id,
            } => {
                assert_eq!(
                    id.miner_output_id(index),
                    miner_output_id,
                    "{name}: miner output"
                );
                assert_eq!(
                    id.foundation_output_id(),
                    foundation_output_id,
                    "{name}: foundation output"
                );
            }
            IdKind::Contract {
                id,
                index,
                valid_output_id,
                missed_output_id,
                renter_output_id,
                host_output_id,
                renewal_id,
            } => {
                assert_eq!(
                    id.valid_output_id(index),
                    valid_output_id,
                    "{name}: valid output"
                );
                assert_eq!(
                    id.missed_output_id(index),
                    missed_output_id,
                    "{name}: missed output"
                );
                assert_eq!(
                    id.v2_renter_output_id(),
                    renter_output_id,
                    "{name}: renter output"
                );
                assert_eq!(
                    id.v2_host_output_id(),
                    host_output_id,
                    "{name}: host output"
                );
                assert_eq!(id.v2_renewal_id(), renewal_id, "{name}: renewal");
            }
            IdKind::Siafund {
                id,
                claim_output_id,
                v2_claim_output_id,
            } => {
                assert_eq!(
                    id.claim_output_id(),
                    claim_output_id,
                    "{name}: claim output"
                );
                assert_eq!(
                    id.v2_claim_output_id(),
                    v2_claim_output_id,
                    "{name}: V2 claim output"
                );
            }
            IdKind::Transaction {
                binary,
                id,
                index,
                siacoin_output_id,
                siafund_output_id,
                file_contract_id,
                attestation_id,
            } => {
                let mut reader = &*binary;
                let txn = v2::Transaction::decode(&mut reader).unwrap();
                assert!(reader.is_empty(), "{name}: trailing bytes");
                assert_eq!(txn.id(), id, "{name}: transaction ID");
                assert_eq!(
                    id.v2_siacoin_output_id(index),
                    siacoin_output_id,
                    "{name}: siacoin output"
                );
                assert_eq!(
                    id.v2_siafund_output_id(index),
                    siafund_output_id,
                    "{name}: siafund output"
                );
                assert_eq!(
                    id.v2_file_contract_id(index),
                    file_contract_id,
                    "{name}: file contract"
                );
                assert_eq!(
                    id.v2_attestation_id(index),
                    attestation_id,
                    "{name}: attestation"
                );
            }
        }
    }
}
