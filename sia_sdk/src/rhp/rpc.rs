use crate::rhp::merkle;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use std::fmt::Display;
use std::marker::PhantomData;
use thiserror::Error;

use super::types::*;
use crate::consensus::ChainState;
use crate::encoding::{Error as EncodingError, SiaEncodable};
use crate::encoding_async::{
    AsyncDecoder, AsyncEncoder, AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable,
    AsyncSiaEncode,
};
use crate::rhp::merkle::ProofValidationError;
use crate::rhp::{self, SECTOR_SIZE};
use blake2b_simd::Params;

use crate::signing::{PrivateKey, PublicKey, Signature};
use crate::types::v2::{FileContract, SatisfiedPolicy, SiacoinElement, SiacoinInput, Transaction};
use crate::types::{
    Address, ChainIndex, Currency, FileContractID, Hash256, Leaf, SiacoinOutput, specifier,
};

macro_rules! impl_rpc_request {
    ($name:ident, $text:literal) => {
        impl RPCRequest for $name {
            async fn encode_request<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
                specifier!($text).encode_async(w).await?;
                self.encode_async(w).await?;
                Ok(())
            }
        }
        impl sealed::Sealed for $name {}
    };
}

macro_rules! impl_rpc_response {
    ($name:ident) => {
        impl RPCResponse for $name {
            async fn encode_response<E: AsyncEncoder>(&self, w: &mut E) -> Result<(), E::Error> {
                false.encode_async(w).await?; // nil error
                self.encode_async(w).await?;
                Ok(())
            }

            async fn decode_response<D: AsyncDecoder>(r: &mut D) -> Result<Self, D::Error>
            where
                D::Error: From<rhp::Error>,
            {
                let has_error = bool::decode_async(r).await?;
                match has_error {
                    false => {
                        let resp = Self::decode_async(r).await?;
                        Ok(resp)
                    }
                    true => {
                        let error = RPCError::decode_async(r).await?;
                        Err(Error::from(error).into())
                    }
                }
            }
        }

        impl sealed::Sealed for $name {}
    };
}

pub trait RenterContractSigner {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, msg: &[u8]) -> Signature;
    fn sign_revision(&self, state: &ChainState, contract: &mut FileContract);
}

impl RenterContractSigner for PrivateKey {
    fn public_key(&self) -> PublicKey {
        self.public_key()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        self.sign(msg)
    }

    fn sign_revision(&self, state: &ChainState, contract: &mut FileContract) {
        let sig_hash = contract.sig_hash(state);
        contract.renter_signature = self.sign(sig_hash.as_ref());
    }
}

pub trait TransactionBuilder {
    fn miner_fee(&self) -> Currency;
    fn fund_transaction(
        &self,
        transaction: &mut Transaction,
        amount: Currency,
    ) -> Result<ChainIndex, RPCError>;
    fn sign_transaction(&self, transaction: &mut Transaction) -> Result<(), RPCError>;
}

/// HostInputsResponse contains the host's Siacoin inputs for funding a
/// formation or resolution transaction.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct HostInputsResponse {
    pub host_inputs: Vec<SiacoinInput>,
}
impl_rpc_response!(HostInputsResponse);

/// RPCFormContractThirdResponse contains the finalized formation
/// transaction set.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct TransactionSetResponse {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
}
impl_rpc_response!(TransactionSetResponse);

/// HostSignatureResponse contains the host's signature for a
/// contract revision.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct HostSignatureResponse {
    pub host_signature: Signature,
}

/// RenterSignatureResponse contains the renter's signature for a
/// contract revision.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RenterSignatureResponse {
    pub renter_signature: Signature,
}

/// RenterResolutionSignaturesResponse contains the renter's signatures for the
/// contract resolution transaction.
///
/// At this point, the host has enough information to broadcast the refresh.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RenterResolutionSignaturesResponse {
    pub renter_renewal_signature: Signature,
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}

/// RPCRefreshContractParams contains the parameters for refreshing a contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
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
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCRefreshContractRequest {
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
    pub fn new<S: RenterContractSigner>(
        signer: S,
        params: RPCRefreshContractRequestParams,
        revision_number: u64,
    ) -> Self {
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
            challenge_signature: signer.sign(state.finalize().as_ref()),
        }
    }
}

/// RPCRenewContractParams contains the parameters for renewing a contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RenewContractParams {
    pub contract_id: FileContractID,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

struct RPCRenewContractRequestParams {
    pub prices: HostPrices,
    pub renewal: RenewContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}

/// RPCRenewContractRequest is the request type for RPCRenewContract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCRenewContractRequest {
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
    pub fn new<S: RenterContractSigner>(
        signer: S,
        params: RPCRenewContractRequestParams,
        revision_number: u64,
    ) -> Self {
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
            challenge_signature: signer.sign(state.finalize().as_ref()),
        }
    }
}

pub struct RPCFreeSectorsRequestParams {
    pub contract_id: FileContractID,
    pub prices: HostPrices,
    pub indices: Vec<u64>,
}

/// RPCFreeSectorsRequest is the request type for removing sectors from a contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCFreeSectorsRequest {
    pub contract_id: FileContractID,
    pub prices: HostPrices,
    pub indices: Vec<u64>,

    pub challenge_signature: Signature,
}

impl RPCFreeSectorsRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(
        signer: S,
        params: RPCFreeSectorsRequestParams,
        revision_number: u64,
    ) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();

        RPCFreeSectorsRequest {
            contract_id: params.contract_id,
            prices: params.prices,
            indices: params.indices,
            challenge_signature: signer.sign(state.finalize().as_ref()),
        }
    }
}

/// RPCFreeSectorsResponse contains the host's old subtree hashes, old leaf hashes,
/// and the new merkle root after freeing sectors.
///
/// The renter must validate the response
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCFreeSectorsResponse {
    pub old_subtree_hashes: Vec<Hash256>,
    pub old_leaf_hashes: Vec<Hash256>,
    pub new_merkle_root: Hash256,
}
impl_rpc_response!(RPCFreeSectorsResponse);

/// RPCLatestRevisionRequest is the request type for getting the latest
/// revision of a file contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCLatestRevisionRequest {
    pub contract_id: FileContractID,
}

/// RPCLatestRevisionResponse contains the latest revision of a file contract,
/// whether it is revisable, and whether it has been renewed.
///
/// If either `revisable` or `renewed` is false, the host will not accept
/// further revisions or renewals of the contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCLatestRevisionResponse {
    pub contract: FileContract,
    pub revisable: bool,
    pub renewed: bool,
}

struct RPCAppendSectorsRequestParams {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    pub contract_id: FileContractID,
}

/// RPCAppendSectorsRequest is the request type for appending sectors to a contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCAppendSectorsRequest {
    pub prices: HostPrices,
    pub sectors: Vec<Hash256>,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}

impl RPCAppendSectorsRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(
        signer: S,
        params: RPCAppendSectorsRequestParams,
        revision_number: u64,
    ) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();
        Self {
            prices: params.prices,
            sectors: params.sectors,
            contract_id: params.contract_id,
            challenge_signature: signer.sign(state.finalize().as_ref()),
        }
    }
}

/// RPCAppendSectorsResponse contains the host's response to an append request.
///
/// It includes the sectors that were accepted, the subtree roots, and the new
/// merkle root after the append operation. The renter must validate the proof
/// against the accepted roots.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCAppendSectorsResponse {
    pub accepted: Vec<bool>,
    pub subtree_roots: Vec<Hash256>,
    pub new_merkle_root: Hash256,
}

/// RPCSectorRootsRequest is the request type for getting the sector roots
/// for a contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCSectorRootsRequest {
    pub prices: HostPrices,
    pub contract_id: FileContractID,
    pub renter_signature: Signature,
    pub offset: u64,
    pub length: u64,
}

/// RPCSectorRootsResponse contains the sector roots and a proof for a contract.
/// The renter must validate the proof against the roots.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCSectorRootsResponse {
    pub proof: Vec<Hash256>,
    pub roots: Vec<Hash256>,
    pub host_signature: Signature,
}

struct RPCReplenishAccountsParams {
    pub accounts: Vec<PublicKey>,
    pub target: Currency,
    pub contract_id: FileContractID,
}

/// RPCReplenishAccountsRequest is the request type for replenishing accounts
/// with Siacoin deposits.
///
/// The host will fund the account to the target amount and send
/// a revision to the renter for verification.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCReplenishAccountsRequest {
    pub accounts: Vec<PublicKey>,
    pub target: Currency,
    pub contract_id: FileContractID,

    pub challenge_signature: Signature,
}

impl RPCReplenishAccountsRequest {
    #[allow(dead_code)] // TODO: remove
    pub fn new<S: RenterContractSigner>(
        signer: S,
        params: RPCReplenishAccountsParams,
        revision_number: u64,
    ) -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        params.accounts.encode(&mut state).unwrap();
        params.target.encode(&mut state).unwrap();
        params.contract_id.encode(&mut state).unwrap();
        revision_number.encode(&mut state).unwrap();

        Self {
            accounts: params.accounts,
            target: params.target,
            contract_id: params.contract_id,
            challenge_signature: signer.sign(state.finalize().as_ref()),
        }
    }
}

/// RPCReplenishAccountsResponse contains the host's response to the replenish
/// request.
///
/// The renter should verify the deposits and construct a revision
/// transferring the funds.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCReplenishAccountsResponse {
    pub deposits: Vec<AccountDeposit>,
}

/// RPCVerifySectorRequest is the request type for verifying the host
/// is storing a sector.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCVerifySectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub leaf_index: u64,
}

/// RPCVerifySectorResponse contains a proof that the host is storing a
/// sector.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCVerifySectorResponse {
    pub proof: Vec<Hash256>,
    pub leaf: Leaf,
}

/// RPCFundAccountsRequest is the request type for funding accounts
/// with Siacoin deposits.
///
/// RPCReplenishAccounts should be preferred
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCFundAccountsRequest {
    pub contract_id: FileContractID,
    pub deposits: Vec<AccountDeposit>,
    pub renter_signature: Signature,
}

/// RPCFundAccountsResponse contains the host's signature and new
/// balance after funding the accounts.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
#[allow(dead_code)] // TODO: use RPC
struct RPCFundAccountsResponse {
    pub balances: Vec<Currency>,
    pub host_signature: Signature,
}

/// RPCError is the error type returned by the RPC server.
#[derive(Debug, PartialEq, AsyncSiaDecode, AsyncSiaEncode)]
pub struct RPCError {
    pub code: u8,
    pub description: String,
}

impl Display for RPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description, self.code)
    }
}

impl std::error::Error for RPCError {}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encoding error: {0}")]
    Encoding(#[from] EncodingError),

    #[error("RPC error: {0}")]
    RPC(#[from] RPCError),

    #[error("not enough host funds {0} < {1}")]
    NotEnoughHostFunds(Currency, Currency),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("expected single file contract in response, found {0}")]
    ExpectedContractTransaction(usize),

    #[error("expected transaction set in response")]
    ExpectedTransactionSet,

    #[error("proof validation failed")]
    ProofValidation(#[from] ProofValidationError),

    #[error(
        "root of uploaded data doesn't match root returned by host: expected {expected}, got {got}"
    )]
    SectorRootMismatch { expected: Hash256, got: Hash256 },
}

#[derive(Debug, Default, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub rpc: Currency,
    pub storage: Currency,
    pub egress: Currency,
    pub ingress: Currency,
    pub account_funding: Currency,
    pub risked_collateral: Currency,
}

impl Usage {
    const fn round_4kib(size: u64) -> u64 {
        (size + 4095) & !4095
    }

    pub fn renter_cost(&self) -> Currency {
        self.rpc + self.storage + self.egress + self.ingress + self.account_funding
    }

    pub fn host_collateral(&self) -> Currency {
        self.risked_collateral
    }

    pub fn write_sector(prices: &HostPrices, data_length: usize) -> Self {
        const TEMP_SECTOR_DURATION: u64 = 144 * 3;
        let data_length = Currency::from(Self::round_4kib(data_length as u64));
        Usage {
            storage: prices.storage_price * data_length * Currency::from(TEMP_SECTOR_DURATION),
            ingress: prices.ingress_price * data_length,
            ..Default::default()
        }
    }

    pub fn read_sector(prices: &HostPrices, data_length: usize) -> Self {
        Usage {
            egress: prices.egress_price * Currency::from(Self::round_4kib(data_length as u64)),
            ..Default::default()
        }
    }

    pub fn sector_roots(prices: &HostPrices, num_roots: usize) -> Self {
        Usage {
            egress: prices.egress_price * Currency::from(Self::round_4kib(32 * (num_roots as u64))),
            ..Default::default()
        }
    }

    pub fn verify_sector(prices: &HostPrices) -> Self {
        Usage {
            egress: prices.egress_price * Currency::from(SECTOR_SIZE),
            ..Default::default()
        }
    }

    pub fn free_sectors(prices: &HostPrices, num_sectors: usize) -> Self {
        Usage {
            rpc: prices.free_sector_price * Currency::from(num_sectors),
            ..Default::default()
        }
    }

    pub fn append_sectors(prices: &HostPrices, num_sectors: usize, duration: u64) -> Self {
        Usage {
            storage: prices.storage_price * Currency::from(num_sectors) * Currency::from(duration),
            ingress: prices.ingress_price
                * Currency::from(Self::round_4kib(32 * num_sectors as u64)),
            risked_collateral: prices.collateral
                * Currency::from(num_sectors)
                * Currency::from(duration),
            ..Default::default()
        }
    }

    pub fn form_contract(prices: &HostPrices) -> Self {
        Usage {
            rpc: prices.contract_price,
            ..Default::default()
        }
    }
}

pub trait RPCRequest: Sized + sealed::Sealed {
    fn encode_request<E: AsyncEncoder>(
        &self,
        w: &mut E,
    ) -> impl Future<Output = Result<(), E::Error>>;
}

pub trait RPCResponse: Sized + sealed::Sealed {
    fn decode_response<D: AsyncDecoder>(r: &mut D) -> impl Future<Output = Result<Self, D::Error>>
    where
        D::Error: From<rhp::Error>;
    fn encode_response<E: AsyncEncoder>(
        &self,
        w: &mut E,
    ) -> impl Future<Output = Result<(), E::Error>>;
}

mod sealed {
    pub trait Sealed {}
}

pub trait Transport {
    type Error: From<Error>;

    fn write_request<R: RPCRequest>(
        &mut self,
        request: &R,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    fn write_response<R: RPCResponse>(
        &mut self,
        response: &R,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    fn read_response<R: RPCResponse>(&mut self) -> impl Future<Output = Result<R, Self::Error>>;
}

/// Marker type for the initial stage of the RPC process.
pub struct RPCInit;

/// Marker type for the waiting stage for host inputs.
pub struct RPCAwaitingHostInputs;

/// Marker type for the waiting stage for host signatures.
pub struct RPCAwaitingHostSignatures;

/// Marker type for the waiting stage for renter signatures.
pub struct RPCAwaitingRenterSignatures;

/// Marker type for the completion stage of the RPC process.
pub struct RPCComplete;

/// RPCSettingsRequest is the request type getting the host's current settings.
/// It is encoded as 0 bytes.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCSettingsRequest {}

impl_rpc_request!(RPCSettingsRequest, "Settings");

/// RPCSettingsResponse is the response type for the RPC settings endpoint.
#[derive(Debug, PartialEq, AsyncSiaDecode, AsyncSiaEncode)]
struct RPCSettingsResponse {
    pub settings: HostSettings,
}
impl_rpc_response!(RPCSettingsResponse);

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RPCSettingsResult {
    pub settings: HostSettings,
    pub usage: Usage,
}

/// RPCSettings returns the host's current settings.
pub struct RPCSettings<T: Transport, State> {
    transport: T,
    state: PhantomData<State>,
}

impl<T: Transport> RPCSettings<T, RPCInit> {
    pub async fn send_request(mut transport: T) -> Result<RPCSettings<T, RPCComplete>, T::Error> {
        transport.write_request(&RPCSettingsRequest {}).await?;

        Ok(RPCSettings {
            transport,
            state: PhantomData,
        })
    }
}

impl<T: Transport> RPCSettings<T, RPCComplete> {
    pub async fn complete(mut self) -> Result<RPCSettingsResult, T::Error> {
        let response: RPCSettingsResponse = self.transport.read_response().await?;
        Ok(RPCSettingsResult {
            settings: response.settings,
            usage: Usage::default(),
        })
    }
}

/// RPCWriteSectorRequest is the request type for writing a sector to the host's
/// temporary storage.
///
/// The host will store the sector for 432 blocks. If the sector is not
/// appended to a contract within that time, it will be deleted.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCWriteSectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub data: Bytes,
}
impl_rpc_request!(RPCWriteSectorRequest, "WriteSector");

/// RPCWriteSectorResponse contains the root hash of the written sector.
///
/// The renter must verify the root hash against the data written.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCWriteSectorResponse {
    pub root: Hash256,
}
impl_rpc_response!(RPCWriteSectorResponse);

/// RPCWriteSectorResult contains the result of a write sector operation,
pub struct RPCWriteSectorResult {
    pub root: Hash256,
    pub usage: Usage,
}

/// RPCWriteSector writes a sector to the host's temporary storage.
/// The host will store the sector for 432 blocks.
/// If the sector is not appended to a contract within that time, it will be deleted.
pub struct RPCWriteSector<T: Transport, State> {
    root: Hash256,
    transport: T,
    usage: Usage,
    state: PhantomData<State>,
}

impl<T: Transport> RPCWriteSector<T, RPCInit> {
    pub async fn send_request(
        mut transport: T,
        prices: HostPrices,
        token: AccountToken,
        data: Bytes,
    ) -> Result<RPCWriteSector<T, RPCComplete>, T::Error> {
        let usage = Usage::write_sector(&prices, data.len());
        let request = RPCWriteSectorRequest {
            prices,
            token,
            data: data.clone(),
        };

        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let root = merkle::sector_root(data.as_ref());
            let _ = tx.send(root).unwrap();
        });

        transport.write_request(&request).await?;
        let root = rx.await.unwrap();

        Ok(RPCWriteSector {
            root,
            transport,
            usage,
            state: PhantomData,
        })
    }
}

impl<T: Transport> RPCWriteSector<T, RPCComplete> {
    pub async fn complete(mut self) -> Result<RPCWriteSectorResult, T::Error> {
        let response: RPCWriteSectorResponse = self.transport.read_response().await?;
        if response.root != self.root {
            return Err(Error::SectorRootMismatch {
                expected: self.root,
                got: response.root,
            }
            .into());
        }

        Ok(RPCWriteSectorResult {
            root: response.root,
            usage: self.usage,
        })
    }
}

/// RPCReadSectorRequest is the request type for reading a sector from the
/// host.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCReadSectorRequest {
    pub prices: HostPrices,
    pub token: AccountToken,
    pub root: Hash256,
    pub offset: u64,
    pub length: u64,
}
impl_rpc_request!(RPCReadSectorRequest, "ReadSector");

/// RPCReadSectorResponse contains the proof and data for a sector read request.
/// The renter must validate the proof against the root hash.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCReadSectorResponse {
    pub data: merkle::RangeProof,
}
impl_rpc_response!(RPCReadSectorResponse);

pub struct RPCReadSectorResult {
    pub data: Bytes,
    pub usage: Usage,
}

/// RPCReadSector reads a sector from the host.
/// The proof must be validated against the expected
/// root hash.
pub struct RPCReadSector<T: Transport, State> {
    transport: T,
    usage: Usage,
    state: PhantomData<State>,
    offset: usize,
    length: usize,
    root: Hash256,
}

impl<T: Transport> RPCReadSector<T, RPCInit> {
    pub async fn send_request(
        mut transport: T,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        offset: usize,
        length: usize,
    ) -> Result<RPCReadSector<T, RPCComplete>, T::Error> {
        let usage = Usage::read_sector(&prices, length);
        let request = RPCReadSectorRequest {
            prices,
            token,
            root,
            offset: offset as u64,
            length: length as u64,
        };
        transport.write_request(&request).await?;

        Ok(RPCReadSector {
            transport,
            usage,
            state: PhantomData,
            offset,
            length,
            root,
        })
    }
}

impl<T: Transport> RPCReadSector<T, RPCComplete> {
    pub async fn complete(mut self) -> Result<RPCReadSectorResult, T::Error> {
        let response: RPCReadSectorResponse = self.transport.read_response().await?;

        // verify proof
        let start = self.offset / SEGMENT_SIZE;
        let end = (self.offset + self.length).div_ceil(SEGMENT_SIZE);
        let data = response
            .data
            .verify(&self.root, start, end)
            .await
            .map_err(Error::ProofValidation)?;

        Ok(RPCReadSectorResult {
            usage: self.usage,
            data,
        })
    }
}

/// RPCAccountBalanceRequest is the request type for getting the balance of
/// an account.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCAccountBalanceRequest {
    pub account: PublicKey,
}
impl_rpc_request!(RPCAccountBalanceRequest, "AccountBalance");

/// RPCAccountBalanceResponse contains the balance of an account.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCAccountBalanceResponse {
    pub balance: Currency,
}
impl_rpc_response!(RPCAccountBalanceResponse);

/// RPCAccountBalanceResult contains the result of an account balance RPC.
pub struct RPCAccountBalanceResult {
    pub balance: Currency,
    pub usage: Usage,
}

/// Requests the current balance of an account.
pub struct RPCAccountBalance<T: Transport, State> {
    transport: T,
    state: PhantomData<State>,
}

impl<T: Transport> RPCAccountBalance<T, RPCInit> {
    pub async fn send_request(
        mut transport: T,
        account: PublicKey,
    ) -> Result<RPCAccountBalance<T, RPCComplete>, T::Error> {
        let request = RPCAccountBalanceRequest { account };
        transport.write_request(&request).await?;

        Ok(RPCAccountBalance {
            transport,
            state: PhantomData,
        })
    }
}

impl<T: Transport> RPCAccountBalance<T, RPCComplete> {
    pub async fn complete(mut self) -> Result<RPCAccountBalanceResult, T::Error> {
        let response: RPCAccountBalanceResponse = self.transport.read_response().await?;
        Ok(RPCAccountBalanceResult {
            balance: response.balance,
            usage: Usage::default(),
        })
    }
}

/// FormContractParams contains the parameters for forming a new contract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct FormContractParams {
    pub renter_public_key: PublicKey,
    pub renter_address: Address,
    pub allowance: Currency,
    pub collateral: Currency,
    pub proof_height: u64,
}

/// RPCFormContractRequest is the request type for RPCFormContract.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RPCFormContractRequest {
    pub prices: HostPrices,
    pub contract: FormContractParams,
    pub miner_fee: Currency,
    pub basis: ChainIndex,
    pub renter_inputs: Vec<SiacoinElement>,
    pub renter_parents: Vec<Transaction>,
}
impl_rpc_request!(RPCFormContractRequest, "FormContract");

/// RenterFormContractSignaturesResponse contains the renter's contract signature and
/// Siacoin input signatures for the contract formation transaction.
///
/// At this point, the host has enough information to broadcast the formation.
#[derive(Debug, PartialEq, AsyncSiaEncode, AsyncSiaDecode)]
struct RenterFormContractSignaturesResponse {
    pub renter_contract_signature: Signature,
    pub renter_satisfied_policies: Vec<SatisfiedPolicy>,
}
impl_rpc_response!(RenterFormContractSignaturesResponse);

pub struct RPCFormContractParams {
    state: ChainState,
    prices: HostPrices,
    contract: FormContractParams,
    host_public_key: PublicKey,
    host_address: Address,
}

pub struct RPCFormContract<T, S, B, State>
where
    T: Transport,
    S: RenterContractSigner,
    B: TransactionBuilder,
{
    transport: T,
    contract_signer: S,
    transaction_builder: B,
    state: PhantomData<State>,

    usage: Usage,
    chain_state: ChainState,
    contract: FileContract,
    formation_transaction: Transaction,
    renter_inputs_len: usize,
}

impl<T: Transport, S: RenterContractSigner, B: TransactionBuilder, State>
    RPCFormContract<T, S, B, State>
{
    pub fn file_contract(&self) -> &FileContract {
        &self.contract
    }

    pub fn formation_transaction(&self) -> &Transaction {
        &self.formation_transaction
    }

    pub fn renter_inputs(&self) -> &[SiacoinInput] {
        &self.formation_transaction.siacoin_inputs[..self.renter_inputs_len]
    }
}

pub struct RPCFormContractResult {
    pub basis: ChainIndex,
    pub transaction_set: Vec<Transaction>,
    pub contract: FileContract,
    pub usage: Usage,
}

impl<T: Transport, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, RPCInit>
{
    pub async fn send_request(
        mut transport: T,
        contract_signer: S,
        transaction_builder: B,
        params: RPCFormContractParams,
    ) -> Result<RPCFormContract<T, S, B, RPCAwaitingHostInputs>, T::Error> {
        let usage = Usage::form_contract(&params.prices);
        let mut contract = FileContract {
            revision_number: 0,
            capacity: 0,
            filesize: 0,
            file_merkle_root: Hash256::default(),
            proof_height: params.contract.proof_height,
            expiration_height: params.contract.proof_height + 144,
            renter_output: SiacoinOutput {
                address: params.contract.renter_address.clone(),
                value: params.contract.allowance,
            },
            host_output: SiacoinOutput {
                address: params.host_address,
                value: params.contract.collateral + params.prices.contract_price,
            },
            missed_host_value: params.contract.collateral,
            total_collateral: params.contract.collateral,
            host_public_key: params.host_public_key,
            renter_public_key: params.contract.renter_public_key,

            host_signature: Signature::default(),
            renter_signature: Signature::default(),
        };
        contract.renter_signature = contract_signer.sign(contract.sig_hash(&params.state).as_ref());

        let miner_fee = transaction_builder.miner_fee() * Currency::new(1000);
        let mut formation_txn = Transaction {
            miner_fee,
            ..Default::default()
        };

        let renter_fund_amount = params.contract.allowance
            + params.prices.contract_price
            + miner_fee
            + contract.tax(&params.state);
        let renter_basis = transaction_builder
            .fund_transaction(&mut formation_txn, renter_fund_amount)
            .map_err(Error::from)?;

        let request = RPCFormContractRequest {
            prices: params.prices,
            miner_fee,
            contract: params.contract,
            basis: renter_basis,
            renter_inputs: formation_txn
                .siacoin_inputs
                .iter()
                .map(|si| si.parent.clone())
                .collect(),
            renter_parents: Vec::new(),
        };
        transport.write_request(&request).await?;

        Ok(RPCFormContract {
            transport,
            contract_signer,
            transaction_builder,
            state: PhantomData,
            usage,
            chain_state: params.state,
            contract,
            renter_inputs_len: formation_txn.siacoin_inputs.len(),
            formation_transaction: formation_txn,
        })
    }
}

impl<T: Transport, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, RPCAwaitingHostInputs>
{
    pub async fn receive_host_inputs(
        mut self,
    ) -> Result<RPCFormContract<T, S, B, RPCAwaitingRenterSignatures>, T::Error> {
        let host_inputs_response: HostInputsResponse = self.transport.read_response().await?;
        let mut formation_txn = self.formation_transaction;

        let host_funding = self.contract.total_collateral;
        let host_sum: Currency = host_inputs_response
            .host_inputs
            .iter()
            .map(|si| si.parent.siacoin_output.value)
            .sum();
        if host_sum < host_funding {
            return Err(Error::NotEnoughHostFunds(host_sum, host_funding).into());
        } else if host_sum > host_funding {
            formation_txn.siacoin_outputs.push(SiacoinOutput {
                address: self.contract.host_output.address.clone(),
                value: host_sum - host_funding,
            });
        }
        formation_txn.siacoin_inputs = host_inputs_response.host_inputs;

        Ok(RPCFormContract {
            transport: self.transport,
            contract_signer: self.contract_signer,
            transaction_builder: self.transaction_builder,
            state: PhantomData,
            usage: self.usage,
            chain_state: self.chain_state,
            contract: self.contract,
            renter_inputs_len: self.renter_inputs_len,
            formation_transaction: formation_txn,
        })
    }
}

impl<T: Transport, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, RPCAwaitingRenterSignatures>
{
    pub fn host_inputs(&self) -> &[SiacoinInput] {
        &self.formation_transaction.siacoin_inputs[self.renter_inputs_len..]
    }

    pub async fn send_renter_signatures(
        mut self,
    ) -> Result<RPCFormContract<T, S, B, RPCComplete>, T::Error> {
        let mut formation_txn = self.formation_transaction;
        let mut contract = self.contract;

        self.contract_signer
            .sign_revision(&self.chain_state, &mut contract);
        self.transaction_builder
            .sign_transaction(&mut formation_txn)
            .map_err(Error::from)?;

        let renter_sigs_response = RenterFormContractSignaturesResponse {
            renter_contract_signature: contract.renter_signature.clone(),
            renter_satisfied_policies: formation_txn.siacoin_inputs[..self.renter_inputs_len]
                .iter()
                .map(|si| si.satisfied_policy.clone())
                .collect(),
        };
        self.transport.write_response(&renter_sigs_response).await?;

        Ok(RPCFormContract {
            transport: self.transport,
            contract_signer: self.contract_signer,
            transaction_builder: self.transaction_builder,
            state: PhantomData,
            usage: self.usage,
            chain_state: self.chain_state,
            renter_inputs_len: self.renter_inputs_len,
            contract,
            formation_transaction: formation_txn,
        })
    }
}

impl<T: Transport, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, RPCComplete>
{
    pub async fn complete(mut self) -> Result<RPCFormContractResult, T::Error> {
        let resp: TransactionSetResponse = self.transport.read_response().await?;
        let formation_txn = resp
            .transaction_set
            .last()
            .ok_or(Error::ExpectedTransactionSet)?;
        if formation_txn.file_contracts.len() != 1 {
            return Err(
                Error::ExpectedContractTransaction(formation_txn.file_contracts.len()).into(),
            );
        }
        let contract = formation_txn.file_contracts.first().unwrap().clone();

        Ok(RPCFormContractResult {
            basis: resp.basis,
            transaction_set: resp.transaction_set,
            contract,
            usage: self.usage,
        })
    }
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use std::io::Cursor;
    use time::OffsetDateTime;
    use tokio::io::AsyncWriteExt;

    use super::*;

    struct BufStream {
        buf: Cursor<Vec<u8>>,
    }

    impl BufStream {
        fn new() -> Self {
            Self {
                buf: Cursor::new(Vec::new()),
            }
        }

        fn inner(self) -> Vec<u8> {
            self.buf.clone().into_inner()
        }
    }

    impl From<Cursor<Vec<u8>>> for BufStream {
        fn from(buf: Cursor<Vec<u8>>) -> Self {
            Self { buf }
        }
    }

    impl AsyncDecoder for BufStream {
        type Error = Error;
        async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            self.buf.decode_buf(buf).await?;
            Ok(())
        }
    }

    impl AsyncEncoder for BufStream {
        type Error = Error;
        async fn encode_buf(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
            self.buf.encode_buf(buf).await?;
            Ok(())
        }
    }

    impl Transport for BufStream {
        type Error = Error;

        async fn write_request<R: RPCRequest>(&mut self, request: &R) -> Result<(), Self::Error> {
            request.encode_request(self).await?;
            self.buf.flush().await?;
            self.buf.set_position(0); // ready to read
            Ok(())
        }

        async fn write_response<R: RPCResponse>(
            &mut self,
            response: &R,
        ) -> Result<(), Self::Error> {
            response.encode_response(self).await?;
            self.buf.flush().await?;
            self.buf.set_position(0); // ready to read
            Ok(())
        }

        async fn read_response<R: RPCResponse>(&mut self) -> Result<R, Self::Error> {
            R::decode_response(self).await
        }
    }

    const TEST_PRICES: HostPrices = HostPrices {
        contract_price: Currency::siacoins(1),
        collateral: Currency::siacoins(2),
        storage_price: Currency::siacoins(3),
        ingress_price: Currency::siacoins(4),
        egress_price: Currency::siacoins(5),
        free_sector_price: Currency::siacoins(6),
        tip_height: 7,
        valid_until: OffsetDateTime::UNIX_EPOCH,
        signature: Signature::new([0u8; 64]),
    };

    const TEST_ACCOUNT_TOKEN: AccountToken = AccountToken {
        host_key: PublicKey::new({
            let mut bytes = [0u8; 32];
            bytes[0] = 10;
            bytes
        }),
        account: PublicKey::new({
            let mut bytes = [0u8; 32];
            bytes[0] = 11;
            bytes
        }),
        valid_until: OffsetDateTime::UNIX_EPOCH,
        signature: Signature::new({
            let mut bytes = [0u8; 64];
            bytes[0] = 13;
            bytes
        }),
    };

    #[tokio::test]
    async fn test_write_request() {
        const EXPECTED_HEX: &str = "52656164536563746f72000000000000000000a1edccce1bc2d300000000000000000042db999d3784a7010000000000000000e3c8666c53467b02000000000000000084b6333b6f084f03000000000000000025a4000a8bca22040000000000000000c691cdd8a68cf604000000000007000000000000000800000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000f000000000000001000000000000000";

        let mut prices = TEST_PRICES;
        prices.valid_until = OffsetDateTime::from_unix_timestamp(8).unwrap();
        prices.signature = Signature::new({
            let mut bytes = [0u8; 64];
            bytes[0] = 9;
            bytes
        });

        let mut token = TEST_ACCOUNT_TOKEN;
        token.valid_until = OffsetDateTime::from_unix_timestamp(12).unwrap();
        token.signature = Signature::new({
            let mut bytes = [0u8; 64];
            bytes[0] = 13;
            bytes
        });

        let mut sig_buf = [0u8; 64];
        sig_buf[0] = 9;
        let req = RPCReadSectorRequest {
            prices,
            token,
            root: Hash256::new({
                let mut bytes = [0u8; 32];
                bytes[0] = 14;
                bytes
            }),
            offset: 15,
            length: 16,
        };

        let mut transport = BufStream::new();
        transport.write_request(&req).await.unwrap();
        assert_eq!(transport.inner(), hex::decode(EXPECTED_HEX).unwrap());
    }

    #[tokio::test]
    async fn test_read_response() {
        const HEX_BYTES: &str = "00030000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000";

        let mut transport = BufStream::from(Cursor::new(hex::decode(HEX_BYTES).unwrap()));
        let resp: RPCFreeSectorsResponse = transport.read_response().await.unwrap();

        let expected = RPCFreeSectorsResponse {
            old_subtree_hashes: vec![
                Hash256::new({
                    let mut bytes = [0u8; 32];
                    bytes[0] = 1;
                    bytes
                }),
                Hash256::new({
                    let mut bytes = [0u8; 32];
                    bytes[0] = 2;
                    bytes
                }),
                Hash256::new({
                    let mut bytes = [0u8; 32];
                    bytes[0] = 3;
                    bytes
                }),
            ],
            old_leaf_hashes: vec![
                Hash256::new({
                    let mut bytes = [0u8; 32];
                    bytes[0] = 4;
                    bytes
                }),
                Hash256::new({
                    let mut bytes = [0u8; 32];
                    bytes[0] = 5;
                    bytes
                }),
                Hash256::new({
                    let mut bytes = [0u8; 32];
                    bytes[0] = 6;
                    bytes
                }),
            ],
            new_merkle_root: Hash256::new({
                let mut bytes = [0u8; 32];
                bytes[0] = 7;
                bytes
            }),
        };

        assert_eq!(resp, expected);
    }

    #[tokio::test]
    async fn test_response_error() {
        const HEX_BYTES: &str = "01010b00000000000000666f6f206261722062617a";

        let mut transport = BufStream::from(Cursor::new(hex::decode(HEX_BYTES).unwrap()));
        let err = transport
            .read_response::<RPCReadSectorResponse>()
            .await
            .unwrap_err();

        let expected_err = RPCError {
            code: 1,
            description: "foo bar baz".to_string(),
        };

        match err {
            Error::RPC(rpc_err) => {
                assert_eq!(rpc_err, expected_err);
            }
            _ => panic!("Expected RPCError, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_rpc_write_sector_send_request() {
        let mut data = BytesMut::zeroed(SECTOR_SIZE);
        rand::fill(&mut data[..]);
        let root = merkle::sector_root(&data);
        let transport = BufStream::new();
        let rpc =
            RPCWriteSector::send_request(transport, TEST_PRICES, TEST_ACCOUNT_TOKEN, data.freeze())
                .await
                .unwrap();
        assert_eq!(rpc.root, root);
    }

    #[tokio::test]
    async fn test_rpc_write_sector_complete() {
        let mut data = BytesMut::zeroed(SECTOR_SIZE);
        rand::fill(&mut data[..]);
        let root = merkle::sector_root(&data);

        // helper to prepare the transport and fill it with the expected host
        // response
        let transport = async || -> BufStream {
            let mut transport = BufStream::new();
            let response = RPCWriteSectorResponse { root };
            transport.write_response(&response).await.unwrap();
            transport
        };

        // perform the RPC with the correct root
        let rpc = RPCWriteSector::<_, RPCComplete> {
            root,
            transport: transport().await,
            usage: Usage::default(),
            state: PhantomData,
        };
        rpc.complete().await.unwrap();

        // change the root to force a mismatch
        let rpc = RPCWriteSector::<_, RPCComplete> {
            root: Hash256::default(),
            transport: transport().await,
            usage: Usage::default(),
            state: PhantomData,
        };
        if let Err(Error::SectorRootMismatch { expected, got }) = rpc.complete().await {
            assert_eq!(expected, Hash256::default());
            assert_eq!(got, root);
        } else {
            panic!("Expected SectorRootMismatch");
        }
    }
}
