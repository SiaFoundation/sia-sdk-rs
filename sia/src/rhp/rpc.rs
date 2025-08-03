use std::error::Error;
use std::fmt::Display;

use crate::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::rhp::SECTOR_SIZE;
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::signing::{PrivateKey, PublicKey, Signature};
use crate::types::v2::{FileContract, SatisfiedPolicy, SiacoinElement, SiacoinInput, Transaction};
use crate::types::{
    specifier, Address, ChainIndex, Currency, FileContractID, Hash256, Leaf, Specifier,
};

const STANDARD_OBJECT_SIZE: usize = 10240; // 10 KiB
const STANDARD_TXNSET_SIZE: usize = 262144; // 256 KiB
const MAX_SECTOR_BATCH_SIZE: usize = 262144; // 1 TiB of sectors
const MAX_ACCOUNT_BATCH_SIZE: usize = 1000;

macro_rules! impl_rpc_object {
    ($type:ty, $max_len:expr) => {
        impl sealed::Sealed for $type {}
        impl RPCObject for $type {
            fn max_len() -> usize {
                $max_len
            }
        }
    };
}

macro_rules! impl_rpc_request {
    ($type:ty, $rpc_id:expr, $max_len:expr) => {
        impl_rpc_object!($type, $max_len);
        impl RPCRequest for $type {
            fn rpc_id(&self) -> Specifier {
                specifier!($rpc_id)
            }
        }
    };
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
            && host_key.verify(&self.sig_hash(), &self.signature)
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

            signature: account_key.sign_hash(&sig_hash),
        }
    }

    pub fn sig_hash(&self) -> Hash256 {
        Self::compute_sig_hash(&self.host_key, &self.account, &self.valid_until)
    }
}

/// An AccountDeposit is an amount of Siacoin to be deposited into an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeposit {
    pub account: PublicKey,
    pub amount: Currency,
}

/// RPCSettingsRequest is the request type for RPCSettings.
#[derive(SiaEncode, SiaDecode)]
pub struct RPCSettingsRequest {}
impl_rpc_request!(RPCSettingsRequest, "RPCSettings", 0);

/// RPCSettingsResponse is the response type for the RPC settings endpoint.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSettingsResponse {
    pub settings: HostSettings,
}
impl_rpc_object!(RPCSettingsResponse, STANDARD_OBJECT_SIZE);

/// RPCFormContractParams contains the parameters for forming a new contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractParams {
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
    pub contract: RPCFormContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}
impl_rpc_request!(
    RPCFormContractRequest,
    "RPCFormContract",
    STANDARD_OBJECT_SIZE
);

/// RPCFormContractResponse contains the host's Siacoin inputs for the contract
/// formation transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractResponse {
    pub host_inputs: Vec<SiacoinInput>,
}
impl_rpc_object!(RPCFormContractResponse, STANDARD_OBJECT_SIZE);

/// RPCFormContractSecondResponse contains the renter's contract signature and
/// Siacoin input signatures for the contract formation transaction.
///
/// At this point, the host has enough information to broadcast the formation.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractSecondResponse {
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}
impl_rpc_object!(RPCFormContractSecondResponse, STANDARD_OBJECT_SIZE);

/// RPCFormContractThirdResponse contains the finalized formation
/// transaction set.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFormContractThirdResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}
impl_rpc_object!(RPCFormContractThirdResponse, STANDARD_TXNSET_SIZE);

/// RPCRefreshContractParams contains the parameters for refreshing a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
}

/// RPCRefreshContractRequest is the request type for RPCRefreshContract.
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
impl_rpc_request!(
    RPCRefreshContractRequest,
    "RPCRefreshContract",
    STANDARD_OBJECT_SIZE
);

/// RPCRefreshContractPartialRequest is the request type for RPCRefreshPartial.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractPartialRequest {
    pub prices: HostPrices,
    pub refresh: RPCRefreshContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,

    pub challenge_signature: Signature,
}
impl_rpc_request!(
    RPCRefreshContractPartialRequest,
    "RPCRefreshPartial",
    STANDARD_OBJECT_SIZE
);

impl RPCRefreshContractRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.refresh.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

/// RPCRefreshContractResponse contains the host's Siacoin inputs for the contract
/// resolution transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractResponse {
    pub host_inputs: Vec<SiacoinInput>,
}
impl_rpc_object!(RPCRefreshContractResponse, STANDARD_OBJECT_SIZE);

/// RPCRefreshContractSecondResponse contains the renter's signatures for the
/// contract refresh transaction.
///
/// At this point, the host has enough information to broadcast the refresh.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractSecondResponse {
    pub renter_renewal_signature: Signature,
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}
impl_rpc_object!(RPCRefreshContractSecondResponse, STANDARD_OBJECT_SIZE);

/// RPCRefreshContractThirdResponse contains the finalized refresh
/// transaction set.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRefreshContractThirdResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}
impl_rpc_object!(RPCRefreshContractThirdResponse, STANDARD_TXNSET_SIZE);

/// RPCRenewContractParams contains the parameters for renewing a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

/// RPCRenewContractRequest is the request type for RPCRenewContract.
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
impl_rpc_request!(
    RPCRenewContractRequest,
    "RPCRenewContract",
    STANDARD_OBJECT_SIZE
);

impl RPCRenewContractRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.renewal.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

/// RPCRenewContractResponse contains the host's Siacoin inputs for the
/// contract renewal transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractResponse {
    pub host_inputs: Vec<SiacoinInput>,
}
impl_rpc_object!(RPCRenewContractResponse, STANDARD_OBJECT_SIZE);

/// RPCRenewContractSecondResponse contains the renter's signatures for the
/// contract renewal transaction.
///
/// At this point, the host has enough information to broadcast the renewal.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractSecondResponse {
    pub renter_renewal_signature: Signature,
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}
impl_rpc_object!(RPCRenewContractSecondResponse, STANDARD_OBJECT_SIZE);

/// RPCRenewContractThirdResponse contains the finalized renewal
/// transaction set.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCRenewContractThirdResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}
impl_rpc_object!(RPCRenewContractThirdResponse, STANDARD_TXNSET_SIZE);

/// RPCFreeSectorsRequest is the request type for removing sectors from a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsRequest {
    pub contract_id: FileContractID,
    pub prices: HostPrices,
    pub indices: Vec<u64>,

    pub challenge_signature: Signature,
}
impl_rpc_request!(
    RPCFreeSectorsRequest,
    "RPCFreeSectors",
    STANDARD_OBJECT_SIZE + (32 * MAX_SECTOR_BATCH_SIZE)
);

impl RPCFreeSectorsRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
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
impl_rpc_object!(RPCFreeSectorsResponse, STANDARD_OBJECT_SIZE);

/// RPCFreeSectorsSecondResponse contains the renter's signature for the
/// contract revision removing the sectors.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsSecondResponse {
    pub renter_signature: Signature,
}
impl_rpc_object!(RPCFreeSectorsSecondResponse, 32);

/// RPCFreeSectorsThirdResponse contains the host's signature for the
/// contract revision removing the sectors.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFreeSectorsThirdResponse {
    pub host_signature: Signature,
}
impl_rpc_object!(RPCFreeSectorsThirdResponse, 32);

/// RPCLatestRevisionRequest is the request type for getting the latest
/// revision of a file contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCLatestRevisionRequest {
    pub contract_id: FileContractID,
}
impl_rpc_request!(
    RPCLatestRevisionRequest,
    "RPCLatestRevision",
    STANDARD_OBJECT_SIZE
);

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
impl_rpc_object!(RPCLatestRevisionResponse, STANDARD_OBJECT_SIZE);

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
impl_rpc_request!(RPCReadSectorRequest, "RPCReadSector", STANDARD_OBJECT_SIZE);

/// RPCReadSectorResponse contains the proof and data for a sector read request.
/// The renter must validate the proof against the root hash.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReadSectorResponse {
    pub proof: Vec<Hash256>,
    pub data: Vec<u8>,
}
impl_rpc_object!(RPCReadSectorResponse, SECTOR_SIZE + STANDARD_OBJECT_SIZE);

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
impl_rpc_request!(
    RPCWriteSectorRequest,
    "RPCWriteSector",
    STANDARD_OBJECT_SIZE + SECTOR_SIZE
);

/// RPCWriteSectorResponse contains the root hash of the written sector.
///
/// The renter must verify the root hash against the data written.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCWriteSectorResponse {
    pub root: Hash256,
}
impl_rpc_object!(RPCWriteSectorResponse, 32);

/// RPCAppendSectorsRequest is the request type for appending sectors to a contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsRequest {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}
impl_rpc_request!(
    RPCAppendSectorsRequest,
    "RPCAppendSectors",
    STANDARD_OBJECT_SIZE + (32 * MAX_SECTOR_BATCH_SIZE)
);

impl RPCAppendSectorsRequest {
    pub fn challenge_sig_hash(&self, revision_number: u64) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        self.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        state.finalize().into()
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
impl_rpc_object!(RPCAppendSectorsResponse, STANDARD_OBJECT_SIZE);

/// RPCAppendSectorsSecondResponse contains the renter's signature for the
/// contract revision appending the sectors.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsSecondResponse {
    pub renter_signature: Signature,
}
impl_rpc_object!(RPCAppendSectorsSecondResponse, 32);

/// RPCAppendSectorsThirdResponse contains the host's signature for the
/// contract revision appending the sectors.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAppendSectorsThirdResponse {
    pub host_signature: Signature,
}
impl_rpc_object!(RPCAppendSectorsThirdResponse, 32);

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
impl_rpc_request!(
    RPCSectorRootsRequest,
    "RPCSectorRoots",
    STANDARD_OBJECT_SIZE
);

/// RPCSectorRootsResponse contains the sector roots and a proof for a contract.
/// The renter must validate the proof against the roots.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCSectorRootsResponse {
    pub proof: Vec<Hash256>,
    pub roots: Vec<Hash256>,
    pub host_signature: Signature,
}
impl_rpc_object!(RPCSectorRootsResponse, STANDARD_OBJECT_SIZE);

/// RPCAccountBalanceRequest is the request type for getting the balance of
/// an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAccountBalanceRequest {
    pub account: PublicKey,
}
impl_rpc_request!(RPCAccountBalanceRequest, "RPCAccountBalance", 32);

/// RPCAccountBalanceResponse contains the balance of an account.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCAccountBalanceResponse {
    pub balance: Currency,
}
impl_rpc_object!(RPCAccountBalanceResponse, 16);

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
impl_rpc_request!(
    RPCReplenishAccountsRequest,
    "RPCReplenishAccounts",
    STANDARD_OBJECT_SIZE + (32 * MAX_ACCOUNT_BATCH_SIZE)
);

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
impl_rpc_object!(
    RPCReplenishAccountsResponse,
    8 + (32 * MAX_ACCOUNT_BATCH_SIZE)
);

/// RPCReplenishAccountsSecondResponse contains the renter's signature for the
/// contract revision replenishing the accounts.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsSecondResponse {
    pub renter_signature: Signature,
}
impl_rpc_object!(RPCReplenishAccountsSecondResponse, 32);

/// RPCReplenishAccountsThirdResponse contains the host's signature for the
/// contract revision replenishing the accounts.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCReplenishAccountsThirdResponse {
    pub host_signature: Signature,
}
impl_rpc_object!(RPCReplenishAccountsThirdResponse, 32);

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
impl_rpc_request!(
    RPCVerifySectorRequest,
    "RPCVerifySector",
    STANDARD_OBJECT_SIZE
);

/// RPCVerifySectorResponse contains a proof that the host is storing a
/// sector.
#[derive(Debug, PartialEq, SiaEncode, SiaDecode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RPCVerifySectorResponse {
    pub proof: Vec<Hash256>,
    pub leaf: Leaf,
}
impl_rpc_object!(RPCVerifySectorResponse, STANDARD_OBJECT_SIZE);

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
impl_rpc_request!(
    RPCFundAccountsRequest,
    "RPCFundAccounts",
    STANDARD_OBJECT_SIZE + (32 * MAX_ACCOUNT_BATCH_SIZE)
);

/// RPCFundAccountsResponse contains the host's signature and new
/// balance after funding the accounts.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCFundAccountsResponse {
    pub balances: Vec<Currency>,
    pub host_signature: Signature,
}
impl_rpc_object!(
    RPCFundAccountsResponse,
    STANDARD_OBJECT_SIZE + (16 * MAX_ACCOUNT_BATCH_SIZE)
);

/// RPCError is the error type returned by the RPC server.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct RPCError {
    pub code: u8,
    pub description: String,
}
impl_rpc_object!(RPCError, STANDARD_OBJECT_SIZE);

impl Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description, self.code)
    }
}

impl Error for RPCError {}

/// RPCObject is the base trait for all RPC objects.
pub trait RPCObject: sealed::Sealed + SiaEncodable + SiaDecodable {
    fn max_len() -> usize;
}

/// RPCRequest is the trait for all RPC requests.
pub trait RPCRequest: RPCObject {
    fn rpc_id(&self) -> Specifier;
}

/// A TransportClient is a trait for sending and receiving RPC requests and responses.
/// It abstracts the underlying transport mechanism, allowing for different implementations
/// (e.g., TCP, QUIC, WebTransport) to be used without changing the RPC logic.
pub trait TransportClient {
    fn write_request<T: RPCRequest>(&self, request: &T) -> Result<(), RPCError>;
    fn write_response<T: RPCObject>(&self, response: &T) -> Result<(), RPCError>;
    fn read_response<T: RPCObject>(&self) -> Result<T, RPCError>;
}

/// sealed is a module to prevent external crates from implementing
/// the RPCObject and RPCRequest traits while still being able
/// to implement a [TransportClient].
mod sealed {
    pub trait Sealed {}
}
