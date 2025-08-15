use sia::consensus::ChainState;
use sia::encoding::{self, SiaDecodable, SiaEncodable};
use sia::rhp::*;
use sia::signing::Signature;
use sia::types::v2::*;
use sia::types::*;
use std::io::{Read, Write};
use std::marker::PhantomData;
use web_transport::{RecvStream, SendStream};

/// A TransportStream is a trait for sending and receiving RPC requests and responses.
/// It abstracts the underlying transport mechanism, allowing for different implementations
/// (e.g., TCP, QUIC, WebTransport) to be used without changing the RPC logic.
pub trait TransportStream: Read + Write {
    fn write_request<R: RPCRequest>(&mut self, request: &R) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.write_all(R::RPC_ID.as_ref())?;
        request.encode(self)?;
        Ok(())
    }

    fn write_response<R: SiaEncodable>(&mut self, response: &R) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.write_all(&[0])?; // nil error
        response.encode(self)?;
        Ok(())
    }

    fn read_response<R: SiaDecodable>(&mut self, max_size: usize) -> Result<R, Error> {
        let mut error_byte = [0u8; 1];
        self.read_exact(&mut error_byte)?;
        match error_byte[0] {
            0 => {
                let mut r = self.take(max_size as u64);
                let resp = R::decode(&mut r)?;
                Ok(resp)
            }
            1 => {
                let mut r = self.take(1024);
                let error = RPCError::decode(&mut r).map(Error::RPC)?;
                Err(error)
            }
            _ => Err(Error::Encoding(encoding::Error::InvalidValue)),
        }
    }
}

impl<T: Read + Write> TransportStream for T {}

/// RPCSettings returns the host's current settings.
pub struct RPCSettings<TransportStream, State> {
    transport: TransportStream,
    state: PhantomData<State>,
}

impl<T: TransportStream> RPCSettings<T, RPCSettingsRequest> {
    pub fn send_request(mut transport: T) -> Result<RPCSettings<T, RPCSettingsResponse>, Error> {
        transport.write_request(&RPCSettingsRequest {})?;

        Ok(RPCSettings {
            transport,
            state: PhantomData,
        })
    }
}

impl<T: TransportStream> RPCSettings<T, RPCSettingsResponse> {
    pub fn complete(mut self) -> Result<RPCSettingsResult, Error> {
        let response: RPCSettingsResponse = self.transport.read_response(STANDARD_OBJECT_SIZE)?;
        Ok(RPCSettingsResult {
            settings: response.settings,
        })
    }
}

pub fn rpc_settings<T: TransportStream>(transport: T) -> Result<RPCSettingsResult, Error> {
    RPCSettings::send_request(transport)?.complete()
}

/// RPCWriteSector writes a sector to the host's temporary storage.
/// The host will store the sector for 432 blocks.
/// If the sector is not appended to a contract within that time, it will be deleted.
pub struct RPCWriteSector<TransportStream, State> {
    transport: TransportStream,
    state: PhantomData<State>,
}

impl<T: TransportStream> RPCWriteSector<T, RPCWriteSectorRequest> {
    pub fn send_request<D: AsRef<[u8]>>(
        mut transport: T,
        prices: HostPrices,
        token: AccountToken,
        data: D,
    ) -> Result<RPCWriteSector<T, RPCWriteSectorResponse>, Error> {
        let data = data.as_ref();
        let request = RPCWriteSectorRequest {
            prices,
            token,
            data_length: data.len(),
        };
        transport.write_request(&request)?;
        transport.write_all(data)?;

        Ok(RPCWriteSector {
            transport,
            state: PhantomData,
        })
    }
}

impl<T: TransportStream> RPCWriteSector<T, RPCWriteSectorResponse> {
    pub fn complete(mut self) -> Result<RPCWriteSectorResult, Error> {
        let response: RPCWriteSectorResponse = self.transport.read_response(32)?;
        Ok(RPCWriteSectorResult {
            root: response.root,
        })
    }
}

/// RPCReadSector reads a sector from the host.
/// The proof must be validated against the expected
/// root hash.
pub struct RPCReadSector<T: TransportStream, State> {
    transport: T,
    state: PhantomData<State>,
}

impl<T: TransportStream> RPCReadSector<T, RPCReadSectorRequest> {
    pub fn send_request(
        mut transport: T,
        prices: HostPrices,
        token: AccountToken,
        root: Hash256,
        length: usize,
        offset: usize,
    ) -> Result<RPCReadSector<T, RPCReadSectorResponse>, Error> {
        let request = RPCReadSectorRequest {
            prices,
            token,
            root,
            length: length as u64,
            offset: offset as u64,
        };
        transport.write_request(&request)?;

        Ok(RPCReadSector {
            transport,
            state: PhantomData,
        })
    }
}

impl<T: TransportStream> RPCReadSector<T, RPCReadSectorResponse> {
    pub fn complete(mut self) -> Result<RPCReadSectorResult, Error> {
        let response: RPCReadSectorResponse =
            self.transport.read_response(1024 + 8 + SECTOR_SIZE)?;
        Ok(RPCReadSectorResult {
            data: response.data,
        })
    }
}

pub struct RPCFormContract<T, S, B, State>
where
    T: TransportStream,
    S: RenterContractSigner,
    B: TransactionBuilder,
{
    transport: T,
    contract_signer: S,
    transaction_builder: B,
    state: PhantomData<State>,

    chain_state: ChainState,
    contract: FileContract,
    formation_transaction: Transaction,
    renter_inputs_len: usize,
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder, State>
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

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, RPCFormContractRequest>
{
    pub fn send_request(
        mut transport: T,
        contract_signer: S,
        transaction_builder: B,
        params: RPCFormContractParams,
    ) -> Result<RPCFormContract<T, S, B, HostInputsResponse>, Error> {
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
        contract.renter_signature = contract_signer.sign(contract.sig_hash(&params.state));

        let miner_fee = transaction_builder.miner_fee() * Currency::new(1000);
        let mut formation_txn = Transaction {
            miner_fee,
            ..Default::default()
        };

        let renter_fund_amount = params.contract.allowance
            + params.prices.contract_price
            + miner_fee
            + contract.tax(&params.state);
        let renter_basis =
            transaction_builder.fund_transaction(&mut formation_txn, renter_fund_amount)?;

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
        transport.write_request(&request)?;

        Ok(RPCFormContract {
            transport,
            contract_signer,
            transaction_builder,
            state: PhantomData,
            chain_state: params.state,
            contract,
            renter_inputs_len: formation_txn.siacoin_inputs.len(),
            formation_transaction: formation_txn,
        })
    }
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, HostInputsResponse>
{
    pub fn receive_host_inputs(
        mut self,
    ) -> Result<RPCFormContract<T, S, B, RenterFormContractSignaturesResponse>, Error> {
        let host_inputs_response: HostInputsResponse = self.transport.read_response(10240)?;
        let mut formation_txn = self.formation_transaction;

        let host_funding = self.contract.total_collateral;
        let host_sum: Currency = host_inputs_response
            .host_inputs
            .iter()
            .map(|si| si.parent.siacoin_output.value)
            .sum();
        if host_sum < host_funding {
            return Err(Error::NotEnoughHostFunds(host_sum, host_funding));
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
            chain_state: self.chain_state,
            contract: self.contract,
            renter_inputs_len: self.renter_inputs_len,
            formation_transaction: formation_txn,
        })
    }
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, RenterFormContractSignaturesResponse>
{
    pub fn host_inputs(&self) -> &[SiacoinInput] {
        &self.formation_transaction.siacoin_inputs[self.renter_inputs_len..]
    }

    pub fn send_renter_signatures(
        mut self,
    ) -> Result<RPCFormContract<T, S, B, TransactionSetResponse>, Error> {
        let mut formation_txn = self.formation_transaction;
        let mut contract = self.contract;

        self.contract_signer
            .sign_revision(&self.chain_state, &mut contract);
        self.transaction_builder
            .sign_transaction(&mut formation_txn)?;

        let renter_sigs_response = RenterFormContractSignaturesResponse {
            renter_contract_signature: contract.renter_signature.clone(),
            renter_satisfied_policies: formation_txn.siacoin_inputs[..self.renter_inputs_len]
                .iter()
                .map(|si| si.satisfied_policy.clone())
                .collect(),
        };
        self.transport.write_response(&renter_sigs_response)?;

        Ok(RPCFormContract {
            transport: self.transport,
            contract_signer: self.contract_signer,
            transaction_builder: self.transaction_builder,
            state: PhantomData,
            chain_state: self.chain_state,
            renter_inputs_len: self.renter_inputs_len,
            contract,
            formation_transaction: formation_txn,
        })
    }
}

impl<T: TransportStream, S: RenterContractSigner, B: TransactionBuilder>
    RPCFormContract<T, S, B, TransactionSetResponse>
{
    pub fn complete(mut self) -> Result<RPCFormContractResult, Error> {
        let resp: TransactionSetResponse = self.transport.read_response(STANDARD_TXNSET_SIZE)?;
        let formation_txn = resp
            .transaction_set
            .last()
            .ok_or(Error::ExpectedTransactionSet)?;
        if formation_txn.file_contracts.len() != 1 {
            return Err(Error::ExpectedContractTransaction(
                formation_txn.file_contracts.len(),
            ));
        }
        let contract = formation_txn.file_contracts.first().unwrap().clone();

        Ok(RPCFormContractResult {
            basis: resp.basis,
            transaction_set: resp.transaction_set,
            contract,
        })
    }
}

pub fn rpc_form_contract<T, S, B>(
    transport: T,
    contract_signer: S,
    transaction_builder: B,
    params: RPCFormContractParams,
) -> Result<RPCFormContractResult, Error>
where
    T: TransportStream,
    S: RenterContractSigner,
    B: TransactionBuilder,
{
    RPCFormContract::send_request(transport, contract_signer, transaction_builder, params)?
        .receive_host_inputs()?
        .send_renter_signatures()?
        .complete()
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn test_write_request() {
        const EXPECTED_HEX: &str = "52656164536563746f72000000000000000000a1edccce1bc2d300000000000000000042db999d3784a7010000000000000000e3c8666c53467b02000000000000000084b6333b6f084f03000000000000000025a4000a8bca22040000000000000000c691cdd8a68cf604000000000007000000000000000800000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000f000000000000001000000000000000";

        let mut buf = Cursor::new(Vec::<u8>::new());
        let mut sig_buf = [0u8; 64];
        sig_buf[0] = 9;
        let req = RPCReadSectorRequest {
            prices: HostPrices {
                contract_price: Currency::siacoins(1),
                collateral: Currency::siacoins(2),
                storage_price: Currency::siacoins(3),
                ingress_price: Currency::siacoins(4),
                egress_price: Currency::siacoins(5),
                free_sector_price: Currency::siacoins(6),
                tip_height: 7,
                valid_until: OffsetDateTime::from_unix_timestamp(8).unwrap(),
                signature: Signature::from({
                    let mut bytes = [0u8; 64];
                    bytes[0] = 9;
                    bytes
                }),
            },
            token: AccountToken {
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
                valid_until: OffsetDateTime::from_unix_timestamp(12).unwrap(),
                signature: Signature::from({
                    let mut bytes = [0u8; 64];
                    bytes[0] = 13;
                    bytes
                }),
            },
            root: Hash256::new({
                let mut bytes = [0u8; 32];
                bytes[0] = 14;
                bytes
            }),
            offset: 15,
            length: 16,
        };
        buf.write_request(&req).unwrap();
        buf.flush().unwrap();
        assert_eq!(buf.into_inner(), hex::decode(EXPECTED_HEX).unwrap());
    }

    #[test]
    fn test_read_response() {
        const HEX_BYTES: &str = "00030000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000";

        let mut buf = Cursor::new(hex::decode(HEX_BYTES).unwrap());
        let resp: RPCFreeSectorsResponse = buf.read_response(1024).unwrap();

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

    #[test]
    fn test_response_error() {
        const HEX_BYTES: &str = "01010b00000000000000666f6f206261722062617a";

        let mut buf = Cursor::new(hex::decode(HEX_BYTES).unwrap());
        let err = buf
            .read_response::<RPCReadSectorResponse>(1024)
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
}
