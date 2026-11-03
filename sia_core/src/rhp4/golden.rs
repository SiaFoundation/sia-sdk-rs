use serde::Deserialize;
use sia_core_derive::cross_target_test;

use super::*;
use crate::encoding_async::AsyncSiaDecodable;
use crate::test_util::{Case, Hex, golden_cases};
use crate::types::FileContractID;
use crate::types::v2::{SatisfiedPolicy, SiacoinElement};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Rhp4Kind {
    HostPrices {
        value: HostPrices,
        hash: Hash256,
        encoding: Hex,
    },
    AccountToken {
        value: AccountToken,
        hash: Hash256,
    },
    #[serde(rename_all = "camelCase")]
    FreeSectors {
        value: FreeSectorsValue,
        hash: Hash256,
        revision_number: u64,
        wire: Hex,
    },
    #[serde(rename_all = "camelCase")]
    AppendSectors {
        value: AppendSectorsValue,
        hash: Hash256,
        revision_number: u64,
        wire: Hex,
    },
    #[serde(rename_all = "camelCase")]
    RenewContract {
        value: RenewContractValue,
        hash: Hash256,
        revision_number: u64,
        wire: Hex,
    },
    #[serde(rename_all = "camelCase")]
    RefreshContract {
        value: RefreshContractValue,
        hash: Hash256,
        revision_number: u64,
        wire: Hex,
    },
    #[serde(rename_all = "camelCase")]
    ReplenishAccounts {
        value: ReplenishAccountsValue,
        hash: Hash256,
        revision_number: u64,
        wire: Hex,
    },
    FormContract {
        value: FormContractValue,
        wire: Hex,
    },
    FormContractSignatures {
        value: FormContractSignaturesValue,
        wire: Hex,
    },
    ReadSector {
        value: ReadSectorValue,
        wire: Hex,
    },
    WriteSector {
        value: WriteSectorValue,
        wire: Hex,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FreeSectorsValue {
    pub prices: HostPrices,
    #[serde(rename = "contractID")]
    pub contract_id: FileContractID,
    pub indices: Vec<u64>,
    pub challenge_signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppendSectorsValue {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    #[serde(rename = "contractID")]
    pub contract_id: FileContractID,
    pub challenge_signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenewalParams {
    #[serde(rename = "contractID")]
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RenewContractValue {
    pub prices: HostPrices,
    pub renewal: RenewalParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
    pub challenge_signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshParams {
    #[serde(rename = "contractID")]
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshContractValue {
    pub prices: HostPrices,
    pub refresh: RefreshParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
    pub challenge_signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReplenishAccountsValue {
    pub accounts: Vec<PublicKey>,
    pub target: Currency,
    #[serde(rename = "contractID")]
    pub contract_id: FileContractID,
    pub challenge_signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FormContractParamsValue {
    pub renter_public_key: PublicKey,
    pub renter_address: Address,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FormContractValue {
    pub prices: HostPrices,
    pub contract: FormContractParamsValue,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FormContractSignaturesValue {
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadSectorValue {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub offset: usize,
    pub length: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WriteSectorValue {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub data_length: usize,
}

#[cross_target_test]
async fn test_go_rhp4_hashes() {
    for Case { name, kind } in golden_cases::<Case<Rhp4Kind>>("rhp4") {
        match kind {
            Rhp4Kind::HostPrices {
                value: prices,
                hash,
                encoding,
            } => {
                let mut encoded = Vec::new();
                prices.encode(&mut encoded).unwrap();
                assert_eq!(encoded, *encoding, "{name}: encoding");
                assert_eq!(
                    prices.encoded_length(),
                    encoding.len(),
                    "{name}: encoded length"
                );
                assert_eq!(
                    HostPrices::decode(&mut &*encoding).unwrap(),
                    prices,
                    "{name}: decode"
                );
                assert_eq!(
                    HostPrices::decode_async(&mut &*encoding).await.unwrap(),
                    prices,
                    "{name}: async decode"
                );
                assert_eq!(prices.sig_hash(), hash, "{name}: sig hash");
            }
            Rhp4Kind::AccountToken { value: token, hash } => {
                assert_eq!(
                    AccountToken::compute_sig_hash(
                        &token.host_key,
                        &token.account,
                        &token.valid_until
                    ),
                    hash,
                    "{name}: sig hash"
                );
            }
            Rhp4Kind::FreeSectors { .. }
            | Rhp4Kind::AppendSectors { .. }
            | Rhp4Kind::RenewContract { .. }
            | Rhp4Kind::RefreshContract { .. }
            | Rhp4Kind::ReplenishAccounts { .. }
            | Rhp4Kind::FormContract { .. }
            | Rhp4Kind::FormContractSignatures { .. }
            | Rhp4Kind::ReadSector { .. }
            | Rhp4Kind::WriteSector { .. } => {}
        }
    }
}
