use std::fmt::Debug;

use sia_core_derive::cross_target_test;

use super::*;
use crate::rhp4::golden::Rhp4Kind;
use crate::test_util::{Case, Hex, golden_cases};

struct ExpectedSigner {
    hash: Hash256,
    signature: Signature,
}

impl RenterContractSigner for ExpectedSigner {
    fn public_key(&self) -> PublicKey {
        unreachable!()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let expected: &[u8] = self.hash.as_ref();
        assert_eq!(msg, expected);
        self.signature.clone()
    }

    fn sign_revision(&self, _: &ChainState, _: &mut FileContract) {
        unreachable!()
    }
}

async fn check_request<T: SiaEncodable + SiaDecodable + Debug + PartialEq>(
    name: &str,
    wire: &Hex,
    id: Specifier,
    request: &T,
) {
    let mut encoded = Vec::new();
    write_request(&mut encoded, id, request).await.unwrap();
    assert_eq!(encoded, **wire, "{name}: wire encoding");
    assert_eq!(
        16 + request.encoded_length(),
        wire.len(),
        "{name}: encoded length"
    );
    let mut body = &wire[16..];
    assert_eq!(&T::decode(&mut body).unwrap(), request, "{name}: decode");
    assert!(body.is_empty(), "{name}: unread bytes");
}

#[cross_target_test]
async fn test_go_rhp4_challenges() {
    for Case { name, kind } in golden_cases::<Case<Rhp4Kind>>("rhp4") {
        match kind {
            Rhp4Kind::FreeSectors {
                value,
                hash,
                revision_number,
                wire,
            } => {
                let signer = ExpectedSigner {
                    hash,
                    signature: value.challenge_signature,
                };
                let request = RPCFreeSectorsRequest::new(
                    signer,
                    RPCFreeSectorsRequestParams {
                        contract_id: value.contract_id,
                        prices: value.prices,
                        indices: value.indices,
                    },
                    revision_number,
                );
                check_request(&name, &wire, specifier!("FreeSectors"), &request).await;
            }
            Rhp4Kind::AppendSectors {
                value,
                hash,
                revision_number,
                wire,
            } => {
                let signer = ExpectedSigner {
                    hash,
                    signature: value.challenge_signature,
                };
                let request = RPCAppendSectorsRequest::new(
                    signer,
                    RPCAppendSectorsRequestParams {
                        prices: value.prices,
                        sectors: value.sectors,
                        contract_id: value.contract_id,
                    },
                    revision_number,
                );
                check_request(&name, &wire, specifier!("AppendSectors"), &request).await;
            }
            Rhp4Kind::RenewContract {
                value,
                hash,
                revision_number,
                wire,
            } => {
                let signer = ExpectedSigner {
                    hash,
                    signature: value.challenge_signature,
                };
                let request = RPCRenewContractRequest::new(
                    signer,
                    RPCRenewContractRequestParams {
                        prices: value.prices,
                        renewal: RenewContractParams {
                            contract_id: value.renewal.contract_id,
                            allowance: value.renewal.allowance,
                            collateral: value.renewal.collateral,
                            proof_height: value.renewal.proof_height,
                        },
                        miner_fee: value.miner_fee,
                        basis: value.basis,
                        renter_inputs: value.renter_inputs,
                        renter_parents: value.renter_parents,
                    },
                    revision_number,
                );
                check_request(&name, &wire, specifier!("RenewContract"), &request).await;
            }
            Rhp4Kind::RefreshContract {
                value,
                hash,
                revision_number,
                wire,
            } => {
                let signer = ExpectedSigner {
                    hash,
                    signature: value.challenge_signature,
                };
                let request = RPCRefreshContractRequest::new(
                    signer,
                    RPCRefreshContractRequestParams {
                        prices: value.prices,
                        refresh: RefreshContractParams {
                            contract_id: value.refresh.contract_id,
                            allowance: value.refresh.allowance,
                            collateral: value.refresh.collateral,
                        },
                        miner_fee: value.miner_fee,
                        basis: value.basis,
                        renter_inputs: value.renter_inputs,
                        renter_parents: value.renter_parents,
                    },
                    revision_number,
                );
                check_request(&name, &wire, specifier!("RefreshContract"), &request).await;
            }
            Rhp4Kind::ReplenishAccounts {
                value,
                hash,
                revision_number,
                wire,
            } => {
                let signer = ExpectedSigner {
                    hash,
                    signature: value.challenge_signature,
                };
                let request = RPCReplenishAccountsRequest::new(
                    signer,
                    RPCReplenishAccountsParams {
                        accounts: value.accounts,
                        target: value.target,
                        contract_id: value.contract_id,
                    },
                    revision_number,
                );
                check_request(&name, &wire, specifier!("ReplAccounts"), &request).await;
            }
            Rhp4Kind::HostPrices { .. }
            | Rhp4Kind::AccountToken { .. }
            | Rhp4Kind::FormContract { .. }
            | Rhp4Kind::FormContractSignatures { .. }
            | Rhp4Kind::ReadSector { .. }
            | Rhp4Kind::WriteSector { .. } => {}
        }
    }
}

#[cross_target_test]
async fn test_go_rhp4_wire_messages() {
    for Case { name, kind } in golden_cases::<Case<Rhp4Kind>>("rhp4") {
        match kind {
            Rhp4Kind::FormContract { value, wire } => {
                let request = RPCFormContractRequest {
                    prices: value.prices,
                    contract: FormContractParams {
                        renter_public_key: value.contract.renter_public_key,
                        renter_address: value.contract.renter_address,
                        allowance: value.contract.allowance,
                        collateral: value.contract.collateral,
                        proof_height: value.contract.proof_height,
                    },
                    basis: value.basis,
                    miner_fee: value.miner_fee,
                    renter_inputs: value.renter_inputs,
                    renter_parents: value.renter_parents,
                };
                check_request(&name, &wire, specifier!("FormContract"), &request).await;
            }
            Rhp4Kind::FormContractSignatures { value, wire } => {
                let response = RenterFormContractSignaturesResponse {
                    renter_contract_signature: value.renter_contract_signature,
                    renter_satisfied_policies: value.renter_satisfied_policies,
                };
                let mut encoded = Vec::new();
                write_response(&mut encoded, &response).await.unwrap();
                assert_eq!(encoded, *wire, "{name}: wire encoding");
                let mut body = &*wire;
                assert!(!bool::decode(&mut body).unwrap(), "{name}: error flag");
                assert_eq!(
                    RenterFormContractSignaturesResponse::decode(&mut body).unwrap(),
                    response,
                    "{name}: decode"
                );
                assert!(body.is_empty(), "{name}: unread bytes");
            }
            Rhp4Kind::ReadSector { value, wire } => {
                let mut encoded = Vec::new();
                RPCReadSector::send_request(
                    &mut encoded,
                    value.prices,
                    value.token,
                    value.root,
                    value.offset,
                    value.length,
                )
                .await
                .unwrap();
                assert_eq!(encoded, *wire, "{name}: wire encoding");
            }
            Rhp4Kind::WriteSector { value, wire } => {
                let data = Bytes::from(vec![0x5a; value.data_length]);
                let mut encoded = Vec::new();
                RPCWriteSector::send_request(&mut encoded, value.prices, value.token, data.clone())
                    .await
                    .unwrap();
                let mut expected = wire.to_vec();
                expected.extend_from_slice(&data);
                assert_eq!(encoded, expected, "{name}: wire encoding");
            }
            Rhp4Kind::HostPrices { .. }
            | Rhp4Kind::AccountToken { .. }
            | Rhp4Kind::FreeSectors { .. }
            | Rhp4Kind::AppendSectors { .. }
            | Rhp4Kind::RenewContract { .. }
            | Rhp4Kind::RefreshContract { .. }
            | Rhp4Kind::ReplenishAccounts { .. } => {}
        }
    }
}
