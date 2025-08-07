use std::marker::PhantomData;

use crate::consensus::ChainState;
use crate::encoding::{SiaDecodable, SiaEncodable};
use crate::rhp::rpc::FormContractParams;
use crate::rhp::SECTOR_SIZE;
use crate::signing::{PublicKey, Signature};
use crate::types::v2::{FileContract, Transaction};
use crate::types::{specifier, Address, Currency, Hash256, SiacoinOutput, Specifier};

use super::rpc::*;

const STANDARD_TXNSET_SIZE: usize = 262144; // 256 KiB

/// A TransportStream is a trait for sending and receiving RPC requests and responses.
/// It abstracts the underlying transport mechanism, allowing for different implementations
/// (e.g., TCP, QUIC, WebTransport) to be used without changing the RPC logic.
pub trait TransportStream {
    fn write_request<T: SiaEncodable>(&self, id: Specifier, request: &T) -> Result<(), RPCError>;
    fn write_response<T: SiaEncodable>(&self, response: &T) -> Result<(), RPCError>;
    fn read_response<T: SiaDecodable>(&self, max_len: usize) -> Result<T, RPCError>;
}

struct Request;
struct ReceiveHostInputs;
struct SendRenterSignatures;
struct HostFinalResponse;

pub struct RPCWriteSectorResult {
    pub root: Hash256,
}

struct RPCWriteSectorSession<T: TransportStream, State> {
    transport: T,
    state: PhantomData<State>,
}

impl<T: TransportStream> RPCWriteSectorSession<T, Request> {
    fn new(transport: T) -> Self {
        RPCWriteSectorSession {
            transport,
            state: PhantomData,
        }
    }

    fn start(
        self,
        prices: HostPrices,
        token: AccountToken,
        data: Vec<u8>,
    ) -> Result<RPCWriteSectorSession<T, HostFinalResponse>, RPCError> {
        let request = RPCWriteSectorRequest {
            prices,
            token,
            data,
        };
        self.transport
            .write_request(specifier!("RPCWriteSector"), &request)?;

        Ok(RPCWriteSectorSession {
            transport: self.transport,
            state: PhantomData,
        })
    }
}

impl<T: TransportStream> RPCWriteSectorSession<T, HostFinalResponse> {
    fn complete(self) -> Result<RPCWriteSectorResult, RPCError> {
        let response: RPCWriteSectorResponse = self.transport.read_response(32)?;
        Ok(RPCWriteSectorResult {
            root: response.root,
        })
    }
}

pub struct RPCReadSectorResult {
    pub data: Vec<u8>,
}

struct RPCReadSectorSession<T: TransportStream, State> {
    transport: T,
    state: PhantomData<State>,
}

impl<T: TransportStream> RPCReadSectorSession<T, Request> {
    fn new(transport: T) -> Self {
        RPCReadSectorSession {
            transport,
            state: PhantomData,
        }
    }

    fn start(
        self,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        length: usize,
        offset: usize,
    ) -> Result<RPCReadSectorSession<T, HostFinalResponse>, RPCError> {
        let request = RPCReadSectorRequest {
            prices,
            token,
            root,
            length: length as u64,
            offset: offset as u64,
        };
        self.transport
            .write_request(specifier!("RPCReadSector"), &request)?;

        Ok(RPCReadSectorSession {
            transport: self.transport,
            state: PhantomData,
        })
    }
}

impl<T: TransportStream> RPCReadSectorSession<T, HostFinalResponse> {
    fn complete(self) -> Result<RPCReadSectorResult, RPCError> {
        let response: RPCReadSectorResponse =
            self.transport.read_response(1024 + 8 + SECTOR_SIZE)?;
        Ok(RPCReadSectorResult {
            data: response.data,
        })
    }
}

pub fn rpc_write_sector<T: TransportStream>(
    transport: T,
    prices: HostPrices,
    token: AccountToken,
    data: Vec<u8>,
) -> Result<RPCWriteSectorResult, RPCError> {
    RPCWriteSectorSession::new(transport)
        .start(prices, token, data)?
        .complete()
}

pub fn rpc_read_sector<T: TransportStream>(
    transport: T,
    prices: HostPrices,
    token: AccountToken,
    root: Hash256,
    length: usize,
    offset: usize,
) -> Result<RPCReadSectorResult, RPCError> {
    RPCReadSectorSession::new(transport)
        .start(prices, token, root, length, offset)?
        .complete()
}

struct RPCFormContractSession<T, S, B, State>
where
    T: TransportStream,
    S: RenterContractSigner,
    B: TransactionBuilder,
{
    transport: T,
    contract_signer: S,
    transaction_builder: B,
    chain_state: ChainState,
    state: PhantomData<State>,

    contract: Option<FileContract>,
    formation_transaction: Option<Transaction>,
    renter_inputs_len: Option<usize>,
}

pub struct RPCFormContractParams {
    prices: HostPrices,
    contract: FormContractParams,
    host_public_key: PublicKey,
    host_address: Address,
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContractSession<T, S, B, Request>
{
    fn new(transport: T, contract_signer: S, transaction_builder: B, state: ChainState) -> Self {
        RPCFormContractSession {
            transport,
            contract_signer,
            transaction_builder,
            chain_state: state,
            state: PhantomData,

            contract: None,
            formation_transaction: None,
            renter_inputs_len: None,
        }
    }

    fn start(
        self,
        params: RPCFormContractParams,
    ) -> Result<RPCFormContractSession<T, S, B, ReceiveHostInputs>, RPCError> {
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
        contract.renter_signature = self
            .contract_signer
            .sign(contract.sig_hash(&self.chain_state));

        let miner_fee = self.transaction_builder.miner_fee() * Currency::new(1000);
        let mut formation_txn = Transaction {
            miner_fee,
            ..Default::default()
        };

        let renter_fund_amount = params.contract.allowance
            + params.prices.contract_price
            + miner_fee
            + contract.tax(&self.chain_state);
        let renter_basis = self
            .transaction_builder
            .fund_transaction(&mut formation_txn, renter_fund_amount)?;

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
        self.transport
            .write_request(specifier!("RPCFormContract"), &request)?;
        Ok(RPCFormContractSession {
            transport: self.transport,
            contract_signer: self.contract_signer,
            transaction_builder: self.transaction_builder,
            chain_state: self.chain_state,
            state: PhantomData,
            contract: Some(contract),
            formation_transaction: Some(formation_txn),
            renter_inputs_len: Some(request.renter_inputs.len()),
        })
    }
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContractSession<T, S, B, ReceiveHostInputs>
{
    fn receive_host_inputs(
        self,
    ) -> Result<RPCFormContractSession<T, S, B, SendRenterSignatures>, RPCError> {
        let host_inputs_response: HostInputsResponse = self.transport.read_response(10240)?;
        let mut formation_txn = self.formation_transaction.unwrap();
        let contract = self.contract.as_ref().unwrap();

        let host_funding = contract.total_collateral;
        let host_sum: Currency = host_inputs_response
            .host_inputs
            .iter()
            .map(|si| si.parent.siacoin_output.value)
            .sum();
        if host_sum < host_funding {
            // TODO: define errors correctly
            return Err(RPCError {
                code: 2,
                description: String::from("not enough host funds"),
            });
        } else if host_sum > host_funding {
            formation_txn.siacoin_outputs.push(SiacoinOutput {
                address: contract.host_output.address.clone(),
                value: host_sum - host_funding,
            });
        }
        formation_txn.siacoin_inputs = host_inputs_response.host_inputs;

        Ok(RPCFormContractSession {
            transport: self.transport,
            contract_signer: self.contract_signer,
            transaction_builder: self.transaction_builder,
            chain_state: self.chain_state,
            state: PhantomData,
            contract: self.contract,
            renter_inputs_len: self.renter_inputs_len,
            formation_transaction: Some(formation_txn),
        })
    }
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContractSession<T, S, B, SendRenterSignatures>
{
    fn send_renter_signatures(
        self,
    ) -> Result<RPCFormContractSession<T, S, B, HostFinalResponse>, RPCError> {
        let mut formation_txn = self.formation_transaction.unwrap();
        let mut contract = self.contract.unwrap();

        self.transaction_builder
            .sign_transaction(&mut formation_txn)?;
        self.contract_signer
            .sign_revision(&self.chain_state, &mut contract);

        let renter_sigs_response = RenterFormContractSignaturesResponse {
            renter_contract_signature: contract.renter_signature.clone(),
            renter_satisfied_policies: formation_txn.siacoin_inputs
                [..self.renter_inputs_len.unwrap()]
                .iter()
                .map(|si| si.satisfied_policy.clone())
                .collect(),
        };
        self.transport.write_response(&renter_sigs_response)?;

        Ok(RPCFormContractSession {
            transport: self.transport,
            contract_signer: self.contract_signer,
            transaction_builder: self.transaction_builder,
            chain_state: self.chain_state,
            state: PhantomData,
            contract: Some(contract),
            formation_transaction: Some(formation_txn),
            renter_inputs_len: self.renter_inputs_len,
        })
    }
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContractSession<T, S, B, HostFinalResponse>
{
    fn complete(self) -> Result<TransactionSetResponse, RPCError> {
        self.transport.read_response(STANDARD_TXNSET_SIZE)
    }
}

pub fn rpc_form_contract<T, S, B>(
    transport: T,
    contract_signer: S,
    transaction_builder: B,
    state: ChainState,
    params: RPCFormContractParams,
) -> Result<TransactionSetResponse, RPCError>
where
    T: TransportStream,
    S: RenterContractSigner,
    B: TransactionBuilder,
{
    RPCFormContractSession::new(transport, contract_signer, transaction_builder, state)
        .start(params)?
        .receive_host_inputs()?
        .send_renter_signatures()?
        .complete()
}
