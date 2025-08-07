use std::error::Error;
use std::fmt::Display;

use crate::consensus::{ChainState};
use crate::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::signing::{PrivateKey, PublicKey, Signature};
use crate::types::v2::{FileContract, SatisfiedPolicy, SiacoinElement, SiacoinInput, Transaction};
use crate::types::{
    Address, ChainIndex, Currency, FileContractID, Hash256, Leaf,
};

pub trait RenterContractSigner {
    fn public_key(&self) -> PublicKey;
    fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Signature;
    fn sign_revision(&self, state: &ChainState, contract: &mut FileContract);
}

impl RenterContractSigner for PrivateKey {
    fn public_key(&self) -> PublicKey {
        self.public_key()
    }

    fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Signature {
        self.sign(msg.as_ref())
    }

    fn sign_revision(&self, state: &ChainState, contract: &mut FileContract) {
        let sig_hash = contract.sig_hash(state);
        contract.renter_signature = self.sign(sig_hash);
    }
}

pub trait TransactionBuilder {
    fn miner_fee(&self) -> Currency;
    fn fund_transaction(&self, transaction: &mut Transaction, amount: Currency) -> Result<ChainIndex, RPCError>;
    fn sign_transaction(&self, transaction: &mut Transaction) -> Result<(), RPCError>;
}

/// Contains the prices and parameters of a host.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostPrices {
    /// The price of forming a new contract with the host.
    pub contract_price: Currency,
    /// The collateral per byte per block the host will
    /// risk for stored data.
    pub collateral: Currency,
    /// The cost of storing a sector on the host per byte per block.
    pub storage_price: Currency,
    /// The cost of uploading data to the host per byte.
    pub ingress_price: Currency,
    /// The cost of downloading data from the host per byte.
    pub egress_price: Currency,
    /// The cost to remove a sector from a contract.
    pub free_sector_price: Currency,
    /// The current height of the host's blockchain.
    pub tip_height: u64,
    /// The time until which the prices are valid.
    pub valid_until: OffsetDateTime,

    pub signature: Signature,
}

impl HostPrices {
    /// Computes the signature hash for the host prices.
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

    /// Checks if the prices are valid for the given host key and timestamp.
    pub fn is_valid(&self, host_key: &PublicKey, timestamp: OffsetDateTime) -> bool {
        self.valid_until > timestamp
            && self.tip_height > 0
            && host_key.verify(self.sig_hash(), &self.signature)
    }
}

/// Contains the settings of a host, including its prices and other parameters.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostSettings {
    /// The version of the protocol the host is using.
    pub protocol_version: [u8; 3],
    /// The current release the host is running.
    pub release: String,
    /// The wallet address of the host to use for contract payments.
    pub wallet_address: Address,
    /// If the host is accepting new contracts.
    pub accepting_contracts: bool,
    /// The maximum amount of collateral that the host will accept for a
    /// single contract.
    pub max_collateral: Currency,
    /// The maximum duration, in blocks, that the host will accept for a contract.
    pub max_contract_duration: u64,
    /// The amount of storage, in sectors, that the host has available.
    pub remaining_storage: u64,
    /// The total amount of storage, in sectors, that the host is offering.
    pub total_storage: u64,
    /// The current prices of the host
    pub prices: HostPrices,
}

/// An account token is used to pay for RPC calls that do not
/// require a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountToken {
    pub host_key: PublicKey,
    pub account: PublicKey,
    pub valid_until: OffsetDateTime,

    pub signature: Signature,
}

impl AccountToken {
    fn compute_sig_hash(
        host_key: &PublicKey,
        account: &PublicKey,
        valid_until: &OffsetDateTime,
    ) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        host_key.encode(&mut state).unwrap();
        account.encode(&mut state).unwrap();
        valid_until.encode(&mut state).unwrap();
        state.finalize().into()
    }

    pub fn new(account_key: &PrivateKey, host_key: PublicKey) -> Self {
        let expiration_time = OffsetDateTime::now_utc() + time::Duration::minutes(5);
        let sig_hash =
            Self::compute_sig_hash(&host_key, &account_key.public_key(), &expiration_time);
        AccountToken {
            host_key,
            account: account_key.public_key(),
            valid_until: expiration_time,

            signature: account_key.sign(sig_hash),
        }
    }
}

/// An AccountDeposit is an amount of Siacoin to be deposited into an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeposit {
    pub account: PublicKey,
    pub amount: Currency,
}


/// HostInputsResponse contains the host's Siacoin inputs for funding a
/// formation or resolution transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostInputsResponse {
    pub host_inputs: Vec<SiacoinInput>,
}

/// RenterFormContractSignaturesResponse contains the renter's contract signature and
/// Siacoin input signatures for the contract formation transaction.
///
/// At this point, the host has enough information to broadcast the formation.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RenterFormContractSignaturesResponse {
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

/// RPCFormContractThirdResponse contains the finalized formation
/// transaction set.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSetResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}

/// HostSignatureResponse contains the host's signature for a
/// contract revision.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct HostSignatureResponse {
    pub host_signature: Signature,
}

/// RenterSignatureResponse contains the renter's signature for a
/// contract revision.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RenterSignatureResponse {
    pub renter_signature: Signature,
}

/// RenterResolutionSignaturesResponse contains the renter's signatures for the
/// contract resolution transaction.
///
/// At this point, the host has enough information to broadcast the refresh.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RenterResolutionSignaturesResponse {
    pub renter_renewal_signature: Signature,
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

/// RPCSettingsResponse is the response type for the RPC settings endpoint.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSettingsResponse {
    pub settings: HostSettings,
}

/// FormContractParams contains the parameters for forming a new contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FormContractParams {
    pub renter_public_key: PublicKey,
    pub renter_address: Address,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

/// RPCFormContractRequest is the request type for RPCFormContract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractRequest {
    pub prices: HostPrices,
    pub contract: FormContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}

/// RPCRefreshContractParams contains the parameters for refreshing a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RefreshContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
}

pub struct RPCRefreshContractRequestParams {
    pub prices: HostPrices,
    pub refresh: RefreshContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}

/// RPCRefreshContractRequest is the request type for RPCRefreshContract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractRequest {
    pub prices: HostPrices,
    pub refresh: RefreshContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,

    pub challenge_signature: Signature,
}

impl RPCRefreshContractRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(signer: S, params: RPCRefreshContractRequestParams, revision_number: u64) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.refresh.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();

        Self {
            prices: params.prices,
            refresh: params.refresh,
            miner_fee: params.miner_fee,
            basis: params.basis,
            renter_inputs: params.renter_inputs,
            renter_parents: params.renter_parents,
            challenge_signature: signer.sign(state.finalize().as_bytes()),
        }
    }
}

/// RPCRenewContractParams contains the parameters for renewing a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RenewContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

pub struct RPCRenewContractRequestParams {
    pub prices: HostPrices,
    pub renewal: RenewContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}

/// RPCRenewContractRequest is the request type for RPCRenewContract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractRequest {
    pub prices: HostPrices,
    pub renewal: RenewContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,

    pub challenge_signature: Signature,
}

impl RPCRenewContractRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(signer: S, params: RPCRenewContractRequestParams, revision_number: u64) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.renewal.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();

        Self {
            prices: params.prices,
            renewal: params.renewal,
            miner_fee: params.miner_fee,
            basis: params.basis,
            renter_inputs: params.renter_inputs,
            renter_parents: params.renter_parents,
            challenge_signature: signer.sign(state.finalize().as_bytes()),
        }
    }
}

pub struct RPCFreeSectorsRequestParams {
    pub contract_id: FileContractID,
    pub prices: HostPrices,
    pub indices: Vec<u64>,
}

/// RPCFreeSectorsRequest is the request type for removing sectors from a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsRequest {
    pub contract_id: FileContractID,
    pub prices: HostPrices,
    pub indices: Vec<u64>,

    pub challenge_signature: Signature,
}

impl RPCFreeSectorsRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(signer: S, params: RPCFreeSectorsRequestParams,  revision_number: u64) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();

        RPCFreeSectorsRequest {
            contract_id: params.contract_id,
            prices: params.prices,
            indices: params.indices,
            challenge_signature: signer.sign(state.finalize().as_bytes()),
        }
    }
}

/// RPCFreeSectorsResponse contains the host's old subtree hashes, old leaf hashes,
/// and the new merkle root after freeing sectors.
///
/// The renter must validate the response
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsResponse {
    pub old_subtree_hashes: Vec<Hash256>,
    pub old_leaf_hashes: Vec<Hash256>,
    pub new_merkle_root: Hash256,
}

/// RPCLatestRevisionRequest is the request type for getting the latest
/// revision of a file contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCLatestRevisionRequest {
    pub contract_id: FileContractID,
}

/// RPCLatestRevisionResponse contains the latest revision of a file contract,
/// whether it is revisable, and whether it has been renewed.
///
/// If either `revisable` or `renewed` is false, the host will not accept
/// further revisions or renewals of the contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCLatestRevisionResponse {
    pub contract: FileContract,
    pub revisable: bool,
    pub renewed: bool,
}

/// RPCReadSectorRequest is the request type for reading a sector from the
/// host.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReadSectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub offset: u64,
    pub length: u64,
}

/// RPCReadSectorResponse contains the proof and data for a sector read request.
/// The renter must validate the proof against the root hash.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReadSectorResponse {
    pub proof: Vec<Hash256>,
    pub data: Vec<u8>,
}

/// RPCWriteSectorRequest is the request type for writing a sector to the host's
/// temporary storage.
///
/// The host will store the sector for 432 blocks. If the sector is not
/// appended to a contract within that time, it will be deleted.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCWriteSectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub data: Vec<u8>,
}

/// RPCWriteSectorResponse contains the root hash of the written sector.
///
/// The renter must verify the root hash against the data written.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCWriteSectorResponse {
    pub root: Hash256,
}

pub struct RPCAppendSectorsRequestParams {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    pub contract_id: FileContractID,
}

/// RPCAppendSectorsRequest is the request type for appending sectors to a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsRequest {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}

impl RPCAppendSectorsRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(signer: S, params: RPCAppendSectorsRequestParams, revision_number: u64) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        Self {
            prices: params.prices,
            sectors: params.sectors,
            contract_id: params.contract_id,
            challenge_signature: signer.sign(state.finalize().as_bytes()),
        }
    }
}

/// RPCAppendSectorsResponse contains the host's response to an append request.
///
/// It includes the sectors that were accepted, the subtree roots, and the new
/// merkle root after the append operation. The renter must validate the proof
/// against the accepted roots.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsResponse {
    pub accepted: Vec<bool>,
    pub subtree_roots: Vec<Hash256>,
    pub new_merkle_root: Hash256,
}

/// RPCSectorRootsRequest is the request type for getting the sector roots
/// for a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSectorRootsRequest {
    pub prices: HostPrices,
    pub contract_id: FileContractID,
    pub renter_signature: Signature,
    pub offset: u64,
    pub length: u64,
}

/// RPCSectorRootsResponse contains the sector roots and a proof for a contract.
/// The renter must validate the proof against the roots.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSectorRootsResponse {
    pub proof: Vec<Hash256>,
    pub roots: Vec<Hash256>,
    pub host_signature: Signature,
}

/// RPCAccountBalanceRequest is the request type for getting the balance of
/// an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAccountBalanceRequest {
    pub account: PublicKey,
}

/// RPCAccountBalanceResponse contains the balance of an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAccountBalanceResponse {
    pub balance: Currency,
}

pub struct RPCReplenishAccountsParams {
    pub accounts: Vec<PublicKey>,
    pub target: Currency,
    pub contract_id: FileContractID,
}

/// RPCReplenishAccountsRequest is the request type for replenishing accounts
/// with Siacoin deposits.
///
/// The host will fund the account to the target amount and send
/// a revision to the renter for verification.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsRequest {
    pub accounts: Vec<PublicKey>,
    pub target: Currency,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}

impl RPCReplenishAccountsRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(signer: S, params: RPCReplenishAccountsParams, revision_number: u64) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.accounts.encode(&mut state).unwrap();
        params.target.encode(&mut state).unwrap();
        params.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();

        Self {
            accounts: params.accounts,
            target: params.target,
            contract_id: params.contract_id,
            challenge_signature: signer.sign(state.finalize().as_bytes()),
        }
    }
}

/// RPCReplenishAccountsResponse contains the host's response to the replenish
/// request.
///
/// The renter should verify the deposits and construct a revision
/// transferring the funds.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsResponse {
    pub deposits: Vec<AccountDeposit>,
}

/// RPCVerifySectorRequest is the request type for verifying the host
/// is storing a sector.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCVerifySectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub leaf_index: u64,
}

/// RPCVerifySectorResponse contains a proof that the host is storing a
/// sector.
#[derive(Debug, PartialEq, SiaEncode, SiaDecode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RPCVerifySectorResponse {
    pub proof: Vec<Hash256>,
    pub leaf: Leaf,
}

/// RPCFundAccountsRequest is the request type for funding accounts
/// with Siacoin deposits.
///
/// RPCReplenishAccounts should be preferred
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFundAccountsRequest {
    pub contract_id: FileContractID,
    pub deposits: Vec<AccountDeposit>,
    pub renter_signature: Signature,
}

/// RPCFundAccountsResponse contains the host's signature and new
/// balance after funding the accounts.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFundAccountsResponse {
    pub balances: Vec<Currency>,
    pub host_signature: Signature,
}

/// RPCError is the error type returned by the RPC server.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCError {
    pub code: u8,
    pub description: String,
}

impl Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description, self.code)
    }
}

impl Error for RPCError {}