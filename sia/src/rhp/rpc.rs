use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use crate::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};

use crate::signing::{PublicKey, Signature};
use crate::types::v2::{FileContract, SatisfiedPolicy, SiacoinElement, SiacoinInput, Transaction};
use crate::types::{Address, ChainIndex, Currency, FileContractID, Hash256};


#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostPrices {
    pub contract_price : Currency,
    pub collateral : Currency,
    pub storage_price: Currency,
    pub ingress_price: Currency,
    pub egress_price: Currency,
    pub free_sector_price : Currency,
    pub tip_height : u64,
    pub valid_until: OffsetDateTime,

    pub signature : Signature,
}

impl HostPrices {
    pub fn sig_hash(&self) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.contract_price.encode(&mut state).unwrap();
        self.collateral.encode(&mut state).unwrap();
        self.storage_price.encode(&mut state).unwrap();
        self.ingress_price.encode(&mut state).unwrap();
        self.egress_price.encode(&mut state).unwrap();
        self.free_sector_price.encode(&mut state).unwrap();
        self.tip_height.encode(&mut state).unwrap();
        self.valid_until.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostSettings {
    pub protocol_version: [u8;3],
    pub release: String,
    pub wallet_address: Address,
    pub accepting_contracts: bool,
    pub max_collateral: Currency,
    pub max_contract_duration: u64,
    pub remaining_storage: u64,
    pub total_storage: u64,
    pub prices: HostPrices,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountToken {
    pub host_key: PublicKey,
    pub account: PublicKey,
    pub valid_until: OffsetDateTime,

    pub signature: Signature,
}

impl AccountToken {
    pub fn sig_hash(&self) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.host_key.encode(&mut state).unwrap();
        self.account.encode(&mut state).unwrap();
        self.valid_until.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeposit {
    pub account: PublicKey,
    pub amount: Currency,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSettingsResponse {
    pub settings: HostSettings,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractParams {
    pub renter_public_key: PublicKey,
    pub renter_address: Address,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractRequest {
    pub prices: HostPrices,
    pub contract: RPCFormContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractResponse {
    pub host_inputs: Vec<SiacoinInput>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractSecondResponse {
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractThirdResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractRequest {
    pub prices: HostPrices,
    pub refresh: RPCRefreshContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,

    pub challenge_signature: Signature,
}

impl RPCRefreshContractRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.refresh.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractResponse {
    pub host_inputs: Vec<SiacoinInput>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractSecondResponse {
    pub renter_renewal_signature: Signature,
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractThirdResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractRequest {
    pub prices: HostPrices,
    pub renewal: RPCRenewContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,

    pub challenge_signature: Signature,
}

impl RPCRenewContractRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.renewal.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractResponse {
    pub host_inputs: Vec<SiacoinInput>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractSecondResponse {
    pub renter_renewal_signature: Signature,
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractThirdResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsRequest {
    pub contract_id: FileContractID,
    pub prices: HostPrices,
    pub indices: Vec<u64>,
    
    pub challenge_signature: Signature,
}

impl RPCFreeSectorsRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsResponse {
    pub old_subtree_hashes: Vec<Hash256>,
    pub old_leaf_hashes: Vec<Hash256>,
    pub new_merkle_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsSecondResponse {
    pub renter_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsThirdResponse {
    pub host_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCLatestRevisionRequest {
    pub contract_id: FileContractID,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCLatestRevisionResponse {
    pub contract: FileContract,
    pub revisable: bool,
    pub renewed: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReadSectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReadSectorResponse {
    pub proof: Vec<Hash256>,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCWriteSectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCWriteSectorResponse {
    pub root: Hash256,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsRequest {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}

impl RPCAppendSectorsRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsResponse {
    pub accepted: Vec<bool>,
    pub subtree_roots: Vec<Hash256>,
    pub new_merkle_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsSecondResponse {
    pub renter_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsThirdResponse {
    pub host_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSectorRootsRequest {
    pub prices: HostPrices,
    pub contract_id: FileContractID,
    pub renter_signature: Signature,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSectorRootsResponse {
    pub proof: Vec<Hash256>,
    pub roots: Vec<Hash256>,
    pub host_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAccountBalanceRequest {
    pub account: PublicKey,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAccountBalanceResponse {
    pub balance: Currency,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsRequest {
    pub accounts: Vec<PublicKey>,
    pub target: Currency,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}

impl RPCReplenishAccountsRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.accounts.encode(&mut state).unwrap();
        self.target.encode(&mut state).unwrap();
        self.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsResponse {
    pub deposits: Vec<AccountDeposit>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsSecondResponse {
    pub renter_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsThirdResponse {
    pub host_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCVerifySectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub leaf_index: u64,
}

#[derive(Debug, PartialEq, SiaEncode, SiaDecode)]
pub struct RPCVerifySectorResponse {
    pub proof: Vec<Hash256>,
    pub leaf: [u8; 64],
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFundAccountsRequest {
    pub contract_id: FileContractID,
    pub deposits: Vec<AccountDeposit>,
    pub renter_signature: Signature,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFundAccountsResponse {
    pub balances: Vec<Currency>,
    pub host_signature: Signature,
}