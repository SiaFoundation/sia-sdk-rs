use core::fmt;
use std::ops::Deref;

use blake2b_simd::Params;
use num_bigint::BigInt;
use num_rational::Ratio;
use num_traits::{FromPrimitive, ToPrimitive};
use serde::de::Error;
use serde::{Deserialize, Serialize};

use crate::consensus::ChainState;
use crate::encoding::{
    self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode,
    V1SiaEncodable, V1SiaEncode,
};
use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable, AsyncSiaEncode};
use crate::merkle::{Accumulator, LEAF_HASH_PREFIX};
use crate::signing::PublicKey;
use crate::types::{Specifier, specifier};

use super::currency::Currency;
use super::{
    Address, FileContractID, Hash256, HexParseError, Leaf, SiacoinOutput, SiacoinOutputID,
    SiafundOutput, SiafundOutputID, StateElement, TransactionID,
};

pub const ALGORITHM_ED25519: Specifier = specifier!["ed25519"];

/// A generic public key that can be used to spend a utxo or revise a file
///  contract
///
/// Currently only supports ed25519 keys
#[derive(
    Debug,
    PartialEq,
    Clone,
    AsyncSiaDecode,
    AsyncSiaEncode,
    SiaEncode,
    V1SiaEncode,
    SiaDecode,
    V1SiaDecode,
)]
pub struct UnlockKey {
    pub algorithm: Specifier,
    pub key: Vec<u8>,
}

impl Serialize for UnlockKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for UnlockKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            UnlockKey::parse_string(&s).map_err(|e| Error::custom(format!("{e:?}")))
        } else {
            let (algorithm, key) = <(Specifier, Vec<u8>)>::deserialize(deserializer)?;
            Ok(Self { algorithm, key })
        }
    }
}

impl fmt::Display for UnlockKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, hex::encode(self.key.as_slice()))
    }
}

impl UnlockKey {
    /// Parses an UnlockKey from a string
    /// The string should be in the format "algorithm:public_key"
    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let (prefix, key_str) = s.split_once(':').ok_or(HexParseError::MissingPrefix)?;
        Ok(UnlockKey {
            algorithm: Specifier::from(prefix),
            key: hex::decode(key_str).map_err(HexParseError::HexError)?,
        })
    }
}

impl From<PublicKey> for UnlockKey {
    fn from(val: PublicKey) -> Self {
        UnlockKey {
            algorithm: ALGORITHM_ED25519,
            key: val.as_ref().to_vec(),
        }
    }
}

/// A FileContractElement is a record of a FileContract within the state accumulator.
pub struct FileContractElement {
    pub state_element: StateElement,
    pub id: FileContractID,
    pub file_contract: FileContract,
}

// specifies the conditions for spending an output or revising a file contract.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    AsyncSiaDecode,
    AsyncSiaEncode,
    SiaEncode,
    SiaDecode,
    V1SiaEncode,
    V1SiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct UnlockConditions {
    pub timelock: u64,
    pub public_keys: Vec<UnlockKey>,
    pub signatures_required: u64,
}

impl UnlockConditions {
    pub fn new(
        timelock: u64,
        public_keys: Vec<UnlockKey>,
        required_signatures: u64,
    ) -> UnlockConditions {
        UnlockConditions {
            timelock,
            public_keys,
            signatures_required: required_signatures,
        }
    }

    pub fn standard_unlock_conditions(public_key: PublicKey) -> UnlockConditions {
        UnlockConditions {
            timelock: 0,
            public_keys: vec![public_key.into()],
            signatures_required: 1,
        }
    }

    pub fn address(&self) -> Address {
        let mut acc = Accumulator::new();
        let mut p = Params::new();
        p.hash_length(32);

        let h = p
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(&self.timelock.to_le_bytes())
            .finalize();

        acc.add_leaf(&h.into());

        for key in self.public_keys.iter() {
            let mut state = p.to_state();
            state.update(LEAF_HASH_PREFIX);
            key.encode(&mut state).unwrap();

            let h = state.finalize();
            acc.add_leaf(&h.into());
        }

        let h = p
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(&self.signatures_required.to_le_bytes())
            .finalize();

        acc.add_leaf(&h.into());

        Address::new(acc.root().into())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInput {
    #[serde(rename = "parentID")]
    pub parent_id: SiacoinOutputID,
    pub unlock_conditions: UnlockConditions,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInput {
    #[serde(rename = "parentID")]
    pub parent_id: SiafundOutputID,
    pub unlock_conditions: UnlockConditions,
    pub claim_address: Address,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContract {
    #[serde(rename = "filesize")]
    pub file_size: u64,
    pub file_merkle_root: Hash256,
    pub window_start: u64,
    pub window_end: u64,
    pub payout: Currency,
    pub valid_proof_outputs: Vec<SiacoinOutput>,
    pub missed_proof_outputs: Vec<SiacoinOutput>,
    pub unlock_hash: Address,
    pub revision_number: u64,
}

impl FileContract {
    pub fn tax(&self, cs: &ChainState) -> Currency {
        let payout = BigInt::from_u128(*self.payout.deref()).unwrap();
        let tax = if cs.child_height() < cs.network.hardfork_tax.height {
            let tax = Ratio::from(payout) * Ratio::from_float(0.039).unwrap();
            tax.numer() / tax.denom()
        } else {
            payout * 39 / 1000
        };
        Currency::new((&tax - &tax % cs.siafund_count()).to_u128().unwrap())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractRevision {
    #[serde(rename = "parentID")]
    pub parent_id: FileContractID,
    pub unlock_conditions: UnlockConditions,
    pub revision_number: u64,
    #[serde(rename = "filesize")]
    pub file_size: u64,
    pub file_merkle_root: Hash256,
    pub window_start: u64,
    pub window_end: u64,
    pub valid_proof_outputs: Vec<SiacoinOutput>,
    pub missed_proof_outputs: Vec<SiacoinOutput>,
    pub unlock_hash: Address,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    #[serde(rename = "parentID")]
    pub parent_id: FileContractID,
    pub leaf: Leaf,
    pub proof: Vec<Hash256>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct CoveredFields {
    pub whole_transaction: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siacoin_inputs: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siacoin_outputs: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contracts: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contract_revisions: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_proofs: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siafund_inputs: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siafund_outputs: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub miner_fees: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arbitrary_data: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<usize>,
}

impl CoveredFields {
    pub fn whole_transaction() -> Self {
        CoveredFields {
            whole_transaction: true,
            ..Default::default()
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignature {
    #[serde(rename = "parentID")]
    pub parent_id: Hash256,
    pub public_key_index: u64,
    pub timelock: u64,
    pub covered_fields: CoveredFields,
    #[serde(with = "crate::types::utils::base64")]
    pub signature: Vec<u8>,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siacoin_inputs: Vec<SiacoinInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siacoin_outputs: Vec<SiacoinOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contracts: Vec<FileContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contract_revisions: Vec<FileContractRevision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_proofs: Vec<StorageProof>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siafund_inputs: Vec<SiafundInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siafund_outputs: Vec<SiafundOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub miner_fees: Vec<Currency>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::types::utils::vec_base64"
    )]
    pub arbitrary_data: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<TransactionSignature>,
}

impl Transaction {
    pub fn encode_no_sigs<W: std::io::Write>(&self, w: &mut W) -> Result<(), encoding::Error> {
        self.siacoin_inputs.encode_v1(w)?;
        self.siacoin_outputs.encode_v1(w)?;
        self.file_contracts.encode_v1(w)?;
        self.file_contract_revisions.encode_v1(w)?;
        self.storage_proofs.encode_v1(w)?;
        self.siafund_inputs.encode_v1(w)?;
        self.siafund_outputs.encode_v1(w)?;
        self.miner_fees.encode_v1(w)?;
        self.arbitrary_data.encode_v1(w)
    }

    pub fn whole_sig_hash<T: AsRef<[u8; 32]>>(
        &self,
        cs: &ChainState,
        parent_id: &T,
        public_key_index: u64,
        timelock: u64,
    ) -> Result<Hash256, encoding::Error> {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(&(self.siacoin_inputs.len() as u64).to_le_bytes());
        for input in self.siacoin_inputs.iter() {
            state.update(cs.replay_prefix());
            input.encode_v1(&mut state)?;
        }

        self.siacoin_outputs.encode_v1(&mut state)?;
        self.file_contracts.encode_v1(&mut state)?;
        self.file_contract_revisions.encode_v1(&mut state)?;
        self.storage_proofs.encode_v1(&mut state)?;

        state.update(&(self.siafund_inputs.len() as u64).to_le_bytes());
        for input in self.siafund_inputs.iter() {
            state.update(cs.replay_prefix());
            input.encode_v1(&mut state)?;
        }

        self.siafund_outputs.encode_v1(&mut state)?;
        self.miner_fees.encode_v1(&mut state)?;
        self.arbitrary_data.encode_v1(&mut state)?;

        state.update(parent_id.as_ref());
        public_key_index.encode_v1(&mut state)?;
        timelock.encode_v1(&mut state)?;

        Ok(state.finalize().into())
    }

    pub fn partial_sig_hash(
        &self,
        cs: &ChainState,
        covered_fields: &CoveredFields,
    ) -> Result<Hash256, encoding::Error> {
        let mut state = Params::new().hash_length(32).to_state();

        for &i in covered_fields.siacoin_inputs.iter() {
            if i >= self.siacoin_inputs.len() {
                return Err(encoding::Error::Custom(
                    "siacoin_inputs index out of bounds".to_string(),
                ));
            }
            state.update(cs.replay_prefix());
            self.siacoin_inputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.siacoin_outputs.iter() {
            if i >= self.siacoin_outputs.len() {
                return Err(encoding::Error::Custom(
                    "siacoin_outputs index out of bounds".to_string(),
                ));
            }
            self.siacoin_outputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.file_contracts.iter() {
            if i >= self.file_contracts.len() {
                return Err(encoding::Error::Custom(
                    "file_contracts index out of bounds".to_string(),
                ));
            }
            self.file_contracts[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.file_contract_revisions.iter() {
            if i >= self.file_contract_revisions.len() {
                return Err(encoding::Error::Custom(
                    "file_contract_revisions index out of bounds".to_string(),
                ));
            }
            self.file_contract_revisions[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.storage_proofs.iter() {
            if i >= self.storage_proofs.len() {
                return Err(encoding::Error::Custom(
                    "storage_proofs index out of bounds".to_string(),
                ));
            }
            self.storage_proofs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.siafund_inputs.iter() {
            if i >= self.siafund_inputs.len() {
                return Err(encoding::Error::Custom(
                    "siafund_inputs index out of bounds".to_string(),
                ));
            }
            state.update(cs.replay_prefix());
            self.siafund_inputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.siafund_outputs.iter() {
            if i >= self.siafund_outputs.len() {
                return Err(encoding::Error::Custom(
                    "siafund_outputs index out of bounds".to_string(),
                ));
            }
            self.siafund_outputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.miner_fees.iter() {
            if i >= self.miner_fees.len() {
                return Err(encoding::Error::Custom(
                    "miner_fees index out of bounds".to_string(),
                ));
            }
            self.miner_fees[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.arbitrary_data.iter() {
            if i >= self.arbitrary_data.len() {
                return Err(encoding::Error::Custom(
                    "arbitrary_data index out of bounds".to_string(),
                ));
            }
            self.arbitrary_data[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.signatures.iter() {
            if i >= self.signatures.len() {
                return Err(encoding::Error::Custom(
                    "signatures index out of bounds".to_string(),
                ));
            }
            self.signatures[i].encode_v1(&mut state)?;
        }
        Ok(state.finalize().into())
    }

    pub fn id(&self) -> TransactionID {
        let mut state = Params::new().hash_length(32).to_state();
        self.encode_no_sigs(&mut state).unwrap();

        state.finalize().into()
    }

    fn derive_child_id<T: From<blake2b_simd::Hash>>(&self, prefix: &Specifier, i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(prefix.as_ref());
        self.encode_no_sigs(&mut state).unwrap();
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    /// siacoin_output_id returns the SiacoinOutputID for the i-th siacoin output of the transaction
    pub fn siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
        const SIACOIN_OUTPUT_ID_PREFIX: Specifier = specifier!("siacoin output");

        self.derive_child_id(&SIACOIN_OUTPUT_ID_PREFIX, i)
    }

    /// siafund_output_id returns the SiafundOutputID for the i-th siafund output of the transaction
    pub fn siafund_output_id(&self, i: usize) -> SiafundOutputID {
        const SIAFUND_OUTPUT_ID_PREFIX: Specifier = specifier!("siafund output");

        self.derive_child_id(&SIAFUND_OUTPUT_ID_PREFIX, i)
    }

    /// file_contract_id returns the FileContractID for the i-th file contract of the transaction
    pub fn file_contract_id(&self, i: usize) -> FileContractID {
        const FILE_CONTRACT_ID_PREFIX: Specifier = specifier!("file contract");

        self.derive_child_id(&FILE_CONTRACT_ID_PREFIX, i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ElementAccumulator, HardforkASIC, HardforkDevAddr, HardforkFoundation, HardforkOak,
        HardforkStorageProof, HardforkTax, HardforkV2, Network, State,
    };
    use crate::seed::Seed;
    use crate::signing::{PrivateKey, PublicKey, Signature};
    use crate::types::{BlockID, ChainIndex, Work};
    use crate::{address, contract_id, hash_256, siacoin_id, siafund_id};
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;
    use std::vec;
    use time::{Duration, OffsetDateTime};

    /// test_serialize_json is a helper to test serialization and deserialization of a struct to and from JSON.
    fn test_serialize_json<S: Serialize + DeserializeOwned + Debug + PartialEq>(
        obj: &S,
        json_str: &str,
    ) {
        let serialized = serde_json::to_string(&obj).unwrap();
        assert_eq!(serialized, json_str);
        let deserialized: S = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, *obj);
    }

    /// test_serialize_v1 is a helper to test serialization and deserialization of a struct to and from Sia's
    /// custom binary encoding.
    fn test_serialize_v1<S: V1SiaEncodable + V1SiaDecodable + Debug + PartialEq>(
        obj: &S,
        hex_binary: &str,
    ) {
        let mut serialized = Vec::new();
        obj.encode_v1(&mut serialized).unwrap();
        assert_eq!(hex::encode(serialized.clone()), hex_binary);
        let deserialized = S::decode_v1(&mut &serialized[..]).unwrap();
        assert_eq!(deserialized, *obj);
    }

    #[test]
    fn test_serialize_unlock_key() {
        let unlock_key: UnlockKey = PublicKey::new([
            0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47, 0xda,
            0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a, 0xd0, 0xdb,
            0x1d, 0x1c, 0xe1, 0xb6,
        ])
        .into();

        // binary
        let mut unlock_key_serialized: Vec<u8> = Vec::new();
        unlock_key.encode(&mut unlock_key_serialized).unwrap();
        assert_eq!(
            unlock_key_serialized,
            [
                0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0xac, 0x1f, 0xfb,
                0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35,
                0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6
            ]
        );
        //assert_eq!(unlock_key_deserialized, unlock_key);

        // json
        let unlock_key_serialized = serde_json::to_string(&unlock_key).unwrap();
        let unlock_key_deserialized: UnlockKey =
            serde_json::from_str(&unlock_key_serialized).unwrap();
        assert_eq!(
            unlock_key_serialized,
            "\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\""
        );
        assert_eq!(unlock_key_deserialized, unlock_key);
    }

    #[test]
    fn test_serialize_unlock_conditions() {
        let unlock_conditions = UnlockConditions::new(
            123,
            vec![
                PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into(),
            ],
            1,
        );

        // binary
        let mut unlock_conditions_serialized: Vec<u8> = Vec::new();
        unlock_conditions
            .encode(&mut unlock_conditions_serialized)
            .unwrap();

        assert_eq!(
            unlock_conditions_serialized,
            [
                123, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16,
                121, 168, 198, 200, 123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60, 40, 140,
                26, 208, 219, 29, 28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        //assert_eq!(unlock_conditions_deserialized, unlock_conditions);

        // json
        let unlock_conditions_serialized = serde_json::to_string(&unlock_conditions).unwrap();
        let unlock_conditions_deserialized: UnlockConditions =
            serde_json::from_str(&unlock_conditions_serialized).unwrap();
        assert_eq!(
            unlock_conditions_serialized,
            "{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1}"
        );
        assert_eq!(unlock_conditions_deserialized, unlock_conditions);
    }

    #[test]
    fn test_serialize_covered_fields() {
        let mut cf = CoveredFields::default();
        cf.siacoin_inputs.push(1);
        cf.siacoin_outputs.push(2);
        cf.siacoin_outputs.push(3);

        let binary_str = "000100000000000000010000000000000002000000000000000200000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize_v1(&cf, binary_str);

        let json_str =
            "{\"wholeTransaction\":false,\"siacoinInputs\":[1],\"siacoinOutputs\":[2,3]}";
        test_serialize_json(&cf, json_str);
    }

    #[test]
    fn test_serialize_siacoin_input() {
        let siacoin_input = SiacoinInput {
            parent_id: siacoin_id!(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
            ),
            unlock_conditions: UnlockConditions::new(
                123,
                vec![
                    PublicKey::new([
                        0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b,
                        0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28,
                        0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                    ])
                    .into(),
                ],
                1,
            ),
        };

        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 123, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0,
            0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16, 121, 168, 198, 200, 123, 71, 218, 29,
            86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26, 208, 219, 29, 28, 225, 182, 1, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&siacoin_input, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1}}";
        test_serialize_json(&siacoin_input, json_str);
    }

    #[test]
    fn test_serialize_siafund_input() {
        let siafund_input = SiafundInput {
            parent_id: siafund_id!(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
            ),
            unlock_conditions: UnlockConditions::new(
                123,
                vec![
                    PublicKey::new([
                        0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b,
                        0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28,
                        0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                    ])
                    .into(),
                ],
                1,
            ),
            claim_address: Address::new(
                hex::decode("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        };

        // binary
        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 123, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0,
            0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16, 121, 168, 198, 200, 123, 71, 218, 29,
            86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26, 208, 219, 29, 28, 225, 182, 1, 0, 0,
            0, 0, 0, 0, 0, 143, 180, 156, 207, 23, 223, 220, 201, 82, 109, 236, 110, 232, 165, 204,
            162, 15, 248, 36, 115, 2, 5, 61, 55, 119, 65, 11, 155, 4, 148, 186, 140,
        ]);
        test_serialize_v1(&siafund_input, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"claimAddress\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0\"}";
        test_serialize_json(&siafund_input, json_str);
    }

    #[test]
    fn test_serialize_transaction_signature() {
        let signature = TransactionSignature {
            parent_id: hash_256!(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
            ),
            public_key_index: 1,
            timelock: 2,
            covered_fields: CoveredFields {
                whole_transaction: true,
                ..Default::default()
            },
            signature: Signature::new([3u8; 64]).data().to_vec(),
        };

        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            64, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        ]);
        test_serialize_v1(&signature, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"publicKeyIndex\":1,\"timelock\":2,\"coveredFields\":{\"wholeTransaction\":true},\"signature\":\"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw==\"}";
        test_serialize_json(&signature, json_str);
    }

    #[test]
    fn test_serialize_filecontract() {
        let contract = FileContract {
            file_size: 1,
            file_merkle_root: Hash256::from([
                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            window_start: 2,
            window_end: 3,
            payout: Currency::new(456),
            valid_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(789),
                address: Address::new([
                    2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            missed_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(101112),
                address: Address::new([
                    3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            unlock_hash: Address::from([
                4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            revision_number: 4,
        };

        let binary_str = hex::encode([
            1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 1, 200, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 21, 2, 2,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 138, 248, 3, 3, 3, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&contract, binary_str.as_str());

        let json_str = "{\"filesize\":1,\"fileMerkleRoot\":\"0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"payout\":\"456\",\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"101112\",\"address\":\"0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"04040400000000000000000000000000000000000000000000000000000000006c604f10c928\",\"revisionNumber\":4}";
        test_serialize_json(&contract, json_str);
    }

    #[test]
    fn test_serialize_filecontract_revision() {
        let revision = FileContractRevision {
            parent_id: FileContractID::from([
                9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            file_size: 1,
            file_merkle_root: Hash256::from([
                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            window_start: 2,
            window_end: 3,
            valid_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(789),
                address: Address::new([
                    2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            missed_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(789),
                address: Address::new([
                    3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            unlock_conditions: UnlockConditions::new(
                123,
                vec![
                    PublicKey::new([
                        0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b,
                        0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28,
                        0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                    ])
                    .into(),
                ],
                1,
            ),
            unlock_hash: Address::from([
                4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            revision_number: 4,
        };

        let binary_str = hex::encode([
            9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49,
            57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16,
            121, 168, 198, 200, 123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26,
            208, 219, 29, 28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 21, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
            0, 0, 3, 21, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&revision, binary_str.as_str());

        let json_str = "{\"parentID\":\"0908070000000000000000000000000000000000000000000000000000000000\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"revisionNumber\":4,\"filesize\":1,\"fileMerkleRoot\":\"0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"789\",\"address\":\"0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"04040400000000000000000000000000000000000000000000000000000000006c604f10c928\"}";
        test_serialize_json(&revision, json_str);
    }

    #[test]
    fn test_serialize_storage_proof() {
        let storage_proof = StorageProof {
            parent_id: contract_id!(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
            ),
            leaf: Leaf::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
            ]),
            proof: vec![
                hash_256!("0102030000000000000000000000000000000000000000000000000000000000"),
                hash_256!("0405060000000000000000000000000000000000000000000000000000000000"),
            ],
        };

        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&storage_proof, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"leaf\":\"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40\",\"proof\":[\"0102030000000000000000000000000000000000000000000000000000000000\",\"0405060000000000000000000000000000000000000000000000000000000000\"]}";
        test_serialize_json(&storage_proof, json_str);
    }

    #[test]
    fn test_serialize_transaction() {
        let transaction = Transaction {
            siacoin_inputs: vec![SiacoinInput {
                parent_id: siacoin_id!(
                    "750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d"
                ),
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![UnlockKey::parse_string(
                        "ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360",
                    )
                    .unwrap()],
                    signatures_required: 6312611591377486220,
                },
            }],
            siacoin_outputs: vec![SiacoinOutput {
                value: Currency::new(890415399000000000000000000000000),
                address: address!("480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7"),
            }],
            file_contracts: vec![
                FileContract{
                    file_size: 0,
                    file_merkle_root: Hash256::default(),
                    window_start: 10536451586783908586,
                    window_end: 9324702155635244357,
                    payout: Currency::new(0),
                    unlock_hash: Address::default(),
                    revision_number: 9657412421282982780,
                    valid_proof_outputs: vec![
                        SiacoinOutput{
                            value: Currency::new(1933513214000000000000000000000000),
                            address: address!("944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0"),
                        }
                    ],
                    missed_proof_outputs: vec![
                       SiacoinOutput{
                            value: Currency::new(2469287901000000000000000000000000),
                            address: address!("1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e"),
                       }
                    ]
                }
            ],
            file_contract_revisions: vec![
                FileContractRevision{
                   parent_id: contract_id!(
                        "e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c"),
                   unlock_conditions: UnlockConditions { timelock: 0, public_keys: vec![UnlockKey::parse_string("ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567").unwrap()], signatures_required: 206644730660526450 },
                   revision_number: 10595710523108536025,
                   file_size: 0,
                   file_merkle_root: Hash256::default(),
                   window_start: 4348934140507359445,
                   window_end: 14012366839994454386,
                   valid_proof_outputs: vec![
                       SiacoinOutput{
                           value: Currency::new(2435858510000000000000000000000000),
                           address: address!("543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f"),
                       }
                   ],
                   missed_proof_outputs: vec![
                        SiacoinOutput{
                        value: Currency::new(880343701000000000000000000000000),
                        address: address!("7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237"),
                        },
                   ],
                   unlock_hash: Address::default(),
                }
            ],
            storage_proofs: vec![
                StorageProof{
                    parent_id: contract_id!(
                        "c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb"),
                    leaf: Leaf::parse_string("b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453").unwrap(),
                    proof: vec![
                        hash_256!("fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de"),
                    ],
                }
            ],
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            miner_fees: vec![
                Currency::new(241119475000000000000000000000000),
            ],
            arbitrary_data: vec![
                vec![218,200,115,32,113,20,37,140,46,52,124,250,115,248,15,207,230,147,17,102,81,78,144,211,153,233,151,247,38,0,42,86]
            ],
            signatures: vec![
                TransactionSignature{
                    parent_id: hash_256!("06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46"),
                    public_key_index: 6088345341283457116,
                    timelock: 2014247885072555224,
                    covered_fields: CoveredFields::whole_transaction(),
                    signature: vec![217,115,68,40,102,107,151,212,97,49,173,137,152,107,47,114,106,144,88,2,23,254,236,109,51,2,231,60,142,149,36,247,23,170,230,250,169,130,46,160,4,225,98,159,77,3,6,157,147,237,70,27,160,151,11,174,160,226,179,163,21,139,141,72],
                },
            ],
        };
        let binary_str = "0100000000000000750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d00000000000000000100000000000000656432353531390000000000000000002000000000000000800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd63608c8111f5cbe69a5701000000000000000e000000000000002be69f532be55cd4697c87000000480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568a010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ea125bc7e4fe3892453df5c634ff6781000000000000000001000000000000000e000000000000005f545e24bc638098ba76be000000944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce8701000000000000000e0000000000000079becb8684da8f5198dafd0000001df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a700000000000000000000000000000000000000000000000000000000000000007c6b04146e0506860100000000000000e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c00000000000000000100000000000000656432353531390000000000000000002000000000000000e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de85677219baa54926de02d9aec01095860b9300000000000000000000000000000000000000000000000000000000000000000000000000000000d58882248f845a3c7211557866ed75c201000000000000000e000000000000007818db5664f130fd08a70e000000543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f01000000000000000e000000000000002b677fe9d9b27794cd88b50000007b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b00000000000000000000000000000000000000000000000000000000000000000100000000000000c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64ebb78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d4530100000000000000fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de0000000000000000000000000000000001000000000000000e000000000000000be35b0b076a36b5d2bfd300000001000000000000002000000000000000dac873207114258c2e347cfa73f80fcfe6931166514e90d399e997f726002a56010000000000000006d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f465cd81a99d4257e54d8dc548fc70bf41b0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000d9734428666b97d46131ad89986b2f726a90580217feec6d3302e73c8e9524f717aae6faa9822ea004e1629f4d03069d93ed461ba0970baea0e2b3a3158b8d48";
        test_serialize_v1(&transaction, binary_str);

        let json_str = "{\"siacoinInputs\":[{\"parentID\":\"750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360\"],\"signaturesRequired\":6312611591377486220}}],\"siacoinOutputs\":[{\"value\":\"890415399000000000000000000000000\",\"address\":\"480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7\"}],\"fileContracts\":[{\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":10536451586783908586,\"windowEnd\":9324702155635244357,\"payout\":\"0\",\"validProofOutputs\":[{\"value\":\"1933513214000000000000000000000000\",\"address\":\"944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0\"}],\"missedProofOutputs\":[{\"value\":\"2469287901000000000000000000000000\",\"address\":\"1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"revisionNumber\":9657412421282982780}],\"fileContractRevisions\":[{\"parentID\":\"e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567\"],\"signaturesRequired\":206644730660526450},\"revisionNumber\":10595710523108536025,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":4348934140507359445,\"windowEnd\":14012366839994454386,\"validProofOutputs\":[{\"value\":\"2435858510000000000000000000000000\",\"address\":\"543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f\"}],\"missedProofOutputs\":[{\"value\":\"880343701000000000000000000000000\",\"address\":\"7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}],\"storageProofs\":[{\"parentID\":\"c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb\",\"leaf\":\"b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453\",\"proof\":[\"fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de\"]}],\"minerFees\":[\"241119475000000000000000000000000\"],\"arbitraryData\":[\"2shzIHEUJYwuNHz6c/gPz+aTEWZRTpDTmemX9yYAKlY=\"],\"signatures\":[{\"parentID\":\"06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46\",\"publicKeyIndex\":6088345341283457116,\"timelock\":2014247885072555224,\"coveredFields\":{\"wholeTransaction\":true},\"signature\":\"2XNEKGZrl9RhMa2JmGsvcmqQWAIX/uxtMwLnPI6VJPcXqub6qYIuoAThYp9NAwadk+1GG6CXC66g4rOjFYuNSA==\"}]}";
        test_serialize_json(&transaction, json_str);
    }

    #[test]
    fn test_transaction_id() {
        let txn = Transaction::default();
        let id = txn.id();
        assert_eq!(
            hex::encode(id),
            "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
        );
    }

    #[test]
    fn test_transaction_whole_sig_hash() {
        let cs = ChainState {
            state: State {
                index: ChainIndex {
                    height: 1,
                    id: BlockID::default(),
                },
                prev_timestamps: [OffsetDateTime::UNIX_EPOCH; 11],
                depth: BlockID::default(),
                child_target: BlockID::default(),
                siafund_pool: Currency::new(0),
                oak_time: Duration::new(0, 0),
                oak_target: BlockID::default(),
                foundation_primary_address: Address::new([0u8; 32]),
                foundation_failsafe_address: Address::new([0u8; 32]),
                total_work: Work::zero(),
                difficulty: Work::zero(),
                oak_work: Work::zero(),
                attestations: 0,
                elements: ElementAccumulator::default(),
            },
            network: Network {
                name: "test".to_string(),
                initial_coinbase: Currency::new(0),
                minimum_coinbase: Currency::new(0),
                initial_target: BlockID::default(),
                block_interval: Duration::new(1, 0),
                maturity_delay: 0,
                hardfork_dev_addr: HardforkDevAddr {
                    height: 0,
                    old_address: Address::new([0u8; 32]),
                    new_address: Address::new([0u8; 32]),
                },
                hardfork_tax: HardforkTax { height: 10 },
                hardfork_storage_proof: HardforkStorageProof { height: 0 },
                hardfork_asic: HardforkASIC {
                    height: 0,
                    oak_time: Duration::new(0, 0),
                    oak_target: BlockID::default(),
                },
                hardfork_oak: HardforkOak {
                    height: 0,
                    fix_height: 0,
                    genesis_timestamp: OffsetDateTime::UNIX_EPOCH,
                },
                hardfork_foundation: HardforkFoundation {
                    height: 0,
                    primary_address: Address::new([0u8; 32]),
                    failsafe_address: Address::new([0u8; 32]),
                },
                hardfork_v2: HardforkV2 {
                    // test was made for pre-v2
                    allow_height: 100,
                    require_height: 100,
                },
            },
        };
        let pk = PrivateKey::from_seed(&[
            136, 215, 58, 248, 45, 30, 78, 97, 128, 111, 82, 204, 43, 233, 223, 111, 110, 29, 73,
            157, 52, 25, 242, 96, 131, 16, 187, 22, 232, 107, 17, 205,
        ]);
        struct TestCase {
            transaction: Transaction,
            parent_id: Hash256,
            timelock: u64,
            key_index: u64,
            expected: &'static str,
        }
        let test_cases = vec![
            TestCase{
                transaction: Transaction {
                    siacoin_inputs: vec![
                        SiacoinInput{
                            parent_id: siacoin_id!("200bd724a6ae87005cd7b3124ae5349addc2d5d8db2fe1cdfb54f80245fc2575"),
                            unlock_conditions: UnlockConditions::standard_unlock_conditions(pk.public_key()),
                        }
                    ],
                    siacoin_outputs: vec![
                        SiacoinOutput{
                            value: Currency::new(67856467336433871),
                            address: address!("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"),
                        }
                    ],
                    file_contracts: Vec::new(),
                    file_contract_revisions: Vec::new(),
                    storage_proofs: Vec::new(),
                    siafund_inputs: Vec::new(),
                    siafund_outputs: Vec::new(),
                    miner_fees: Vec::new(),
                    arbitrary_data: Vec::new(),
                    signatures: Vec::new(),
                },
                parent_id: hash_256!("200bd724a6ae87005cd7b3124ae5349addc2d5d8db2fe1cdfb54f80245fc2575"),
                timelock: 0,
                key_index: 0,
                expected: "a4b1855c546db7ec902237f730717faae96187db8ce9fe139504323a639f731e"
            },
            TestCase{
                transaction: serde_json::from_str("{\"siacoinInputs\":[{\"parentID\":\"750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360\"],\"signaturesRequired\":6312611591377486220}}],\"siacoinOutputs\":[{\"value\":\"890415399000000000000000000000000\",\"address\":\"480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7\"}],\"fileContracts\":[{\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":10536451586783908586,\"windowEnd\":9324702155635244357,\"payout\":\"0\",\"validProofOutputs\":[{\"value\":\"1933513214000000000000000000000000\",\"address\":\"944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0\"}],\"missedProofOutputs\":[{\"value\":\"2469287901000000000000000000000000\",\"address\":\"1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"revisionNumber\":9657412421282982780}],\"fileContractRevisions\":[{\"parentID\":\"e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567\"],\"signaturesRequired\":206644730660526450},\"revisionNumber\":10595710523108536025,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":4348934140507359445,\"windowEnd\":14012366839994454386,\"validProofOutputs\":[{\"value\":\"2435858510000000000000000000000000\",\"address\":\"543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f\"}],\"missedProofOutputs\":[{\"value\":\"880343701000000000000000000000000\",\"address\":\"7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}],\"storageProofs\":[{\"parentID\":\"c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb\",\"leaf\":\"b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453\",\"proof\":[\"fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de\"]}],\"minerFees\":[\"241119475000000000000000000000000\"],\"arbitraryData\":[\"2shzIHEUJYwuNHz6c/gPz+aTEWZRTpDTmemX9yYAKlY=\"],\"signatures\":[{\"parentID\":\"06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46\",\"publicKeyIndex\":6088345341283457116,\"timelock\":2014247885072555224,\"coveredFields\":{\"wholeTransaction\":true},\"signature\":\"2XNEKGZrl9RhMa2JmGsvcmqQWAIX/uxtMwLnPI6VJPcXqub6qYIuoAThYp9NAwadk+1GG6CXC66g4rOjFYuNSA==\"}]}").expect("valid transaction"),
                parent_id: hash_256!("59c36e89224f681c1a843c3f30e12c77823d17581d4061724ec6d61555c49095"),
                timelock: 0,
                key_index: 0,
                expected: "f93b095e09f8c860ba8638737ba5f4c81a311af1a840c6b18635009e4d90574e",
            },
            TestCase{
                transaction: serde_json::from_str("{\"siacoinInputs\":[{\"parentID\":\"750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360\"],\"signaturesRequired\":6312611591377486220}}],\"siacoinOutputs\":[{\"value\":\"890415399000000000000000000000000\",\"address\":\"480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7\"}],\"fileContracts\":[{\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":10536451586783908586,\"windowEnd\":9324702155635244357,\"payout\":\"0\",\"validProofOutputs\":[{\"value\":\"1933513214000000000000000000000000\",\"address\":\"944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0\"}],\"missedProofOutputs\":[{\"value\":\"2469287901000000000000000000000000\",\"address\":\"1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"revisionNumber\":9657412421282982780}],\"fileContractRevisions\":[{\"parentID\":\"e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567\"],\"signaturesRequired\":206644730660526450},\"revisionNumber\":10595710523108536025,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":4348934140507359445,\"windowEnd\":14012366839994454386,\"validProofOutputs\":[{\"value\":\"2435858510000000000000000000000000\",\"address\":\"543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f\"}],\"missedProofOutputs\":[{\"value\":\"880343701000000000000000000000000\",\"address\":\"7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}],\"storageProofs\":[{\"parentID\":\"c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb\",\"leaf\":\"b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453\",\"proof\":[\"fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de\"]}],\"minerFees\":[\"241119475000000000000000000000000\"],\"arbitraryData\":[\"2shzIHEUJYwuNHz6c/gPz+aTEWZRTpDTmemX9yYAKlY=\"],\"signatures\":[{\"parentID\":\"06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46\",\"publicKeyIndex\":6088345341283457116,\"timelock\":2014247885072555224,\"coveredFields\":{\"wholeTransaction\":true},\"signature\":\"2XNEKGZrl9RhMa2JmGsvcmqQWAIX/uxtMwLnPI6VJPcXqub6qYIuoAThYp9NAwadk+1GG6CXC66g4rOjFYuNSA==\"}]}").expect("valid transaction"),
                parent_id: hash_256!("59c36e89224f681c1a843c3f30e12c77823d17581d4061724ec6d61555c49095"),
                timelock: 467251739279473577,
                key_index: 1493934879227647507,
                expected: "7aea4ec52e1f7de90261c4448a928081d4be6015252e482ec9c1cfa01663d768",
            },
        ];

        for (i, case) in test_cases.iter().enumerate() {
            let sig_hash = case
                .transaction
                .whole_sig_hash(&cs, &case.parent_id, case.key_index, case.timelock)
                .expect("encoded sig hash");
            assert_eq!(sig_hash.to_string(), case.expected, "case {i}")
        }
    }

    #[test]
    fn test_transaction_partial_sig_hash() {
        let cs = ChainState {
            state: State {
                index: ChainIndex {
                    height: 1,
                    id: BlockID::default(),
                },
                prev_timestamps: [OffsetDateTime::UNIX_EPOCH; 11],
                depth: BlockID::default(),
                child_target: BlockID::default(),
                siafund_pool: Currency::new(0),
                oak_time: Duration::new(0, 0),
                oak_target: BlockID::default(),
                foundation_primary_address: Address::new([0u8; 32]),
                foundation_failsafe_address: Address::new([0u8; 32]),
                total_work: Work::zero(),
                difficulty: Work::zero(),
                oak_work: Work::zero(),
                attestations: 0,
                elements: ElementAccumulator::default(),
            },
            network: Network {
                name: "test".to_string(),
                initial_coinbase: Currency::new(0),
                minimum_coinbase: Currency::new(0),
                initial_target: BlockID::default(),
                block_interval: Duration::new(1, 0),
                maturity_delay: 0,
                hardfork_dev_addr: HardforkDevAddr {
                    height: 0,
                    old_address: Address::new([0u8; 32]),
                    new_address: Address::new([0u8; 32]),
                },
                hardfork_tax: HardforkTax { height: 10 },
                hardfork_storage_proof: HardforkStorageProof { height: 0 },
                hardfork_asic: HardforkASIC {
                    height: 0,
                    oak_time: Duration::new(0, 0),
                    oak_target: BlockID::default(),
                },
                hardfork_oak: HardforkOak {
                    height: 0,
                    fix_height: 0,
                    genesis_timestamp: OffsetDateTime::UNIX_EPOCH,
                },
                hardfork_foundation: HardforkFoundation {
                    height: 0,
                    primary_address: Address::new([0u8; 32]),
                    failsafe_address: Address::new([0u8; 32]),
                },
                hardfork_v2: HardforkV2 {
                    // test was made for pre-v2
                    allow_height: 100,
                    require_height: 100,
                },
            },
        };
        let txn: Transaction = serde_json::from_str("{\"siacoinInputs\":[{\"parentID\":\"750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360\"],\"signaturesRequired\":6312611591377486220}}],\"siacoinOutputs\":[{\"value\":\"890415399000000000000000000000000\",\"address\":\"480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7\"}],\"fileContracts\":[{\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":10536451586783908586,\"windowEnd\":9324702155635244357,\"payout\":\"0\",\"validProofOutputs\":[{\"value\":\"1933513214000000000000000000000000\",\"address\":\"944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0\"}],\"missedProofOutputs\":[{\"value\":\"2469287901000000000000000000000000\",\"address\":\"1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"revisionNumber\":9657412421282982780}],\"fileContractRevisions\":[{\"parentID\":\"e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567\"],\"signaturesRequired\":206644730660526450},\"revisionNumber\":10595710523108536025,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"windowStart\":4348934140507359445,\"windowEnd\":14012366839994454386,\"validProofOutputs\":[{\"value\":\"2435858510000000000000000000000000\",\"address\":\"543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f\"}],\"missedProofOutputs\":[{\"value\":\"880343701000000000000000000000000\",\"address\":\"7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237\"}],\"unlockHash\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}],\"storageProofs\":[{\"parentID\":\"c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb\",\"leaf\":\"b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453\",\"proof\":[\"fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de\"]}],\"minerFees\":[\"241119475000000000000000000000000\"],\"arbitraryData\":[\"2shzIHEUJYwuNHz6c/gPz+aTEWZRTpDTmemX9yYAKlY=\"],\"signatures\":[{\"parentID\":\"06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46\",\"publicKeyIndex\":6088345341283457116,\"timelock\":2014247885072555224,\"coveredFields\":{\"wholeTransaction\":true},\"signature\":\"2XNEKGZrl9RhMa2JmGsvcmqQWAIX/uxtMwLnPI6VJPcXqub6qYIuoAThYp9NAwadk+1GG6CXC66g4rOjFYuNSA==\"}]}").expect("valid transaction");

        let test_cases = vec![
            (
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![0],
                    siacoin_outputs: vec![0],
                    file_contracts: vec![0],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![0],
                    siafund_inputs: vec![],
                    siafund_outputs: vec![],
                    miner_fees: vec![0],
                    arbitrary_data: vec![0],
                    signatures: vec![0],
                },
                "5a9a69acb9211dc952b7458754e9fdf7f86fef419c03e8054f992d95c14ebf63",
            ),
            (
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![],
                    siacoin_outputs: vec![0],
                    file_contracts: vec![0],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![0],
                    siafund_inputs: vec![],
                    siafund_outputs: vec![],
                    miner_fees: vec![0],
                    arbitrary_data: vec![0],
                    signatures: vec![0],
                },
                "81c3e106089f1c86f3402c3bbc0d572d49eafe559961b18344102de4ee1abd94",
            ),
            (
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![0],
                    siacoin_outputs: vec![],
                    file_contracts: vec![0],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![0],
                    siafund_inputs: vec![],
                    siafund_outputs: vec![],
                    miner_fees: vec![0],
                    arbitrary_data: vec![0],
                    signatures: vec![0],
                },
                "78d8dca99a5a775e5223867af702bf6304326784c4e7f3fd431043504a7f7a98",
            ),
            (
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![0],
                    siacoin_outputs: vec![0],
                    file_contracts: vec![0],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![0],
                    siafund_inputs: vec![],
                    siafund_outputs: vec![],
                    miner_fees: vec![0],
                    arbitrary_data: vec![],
                    signatures: vec![0],
                },
                "79efc21fbdbf9536fe90b49b4858d5e2945a6bcb28f82b49b189d793f22f150b",
            ),
            (
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![],
                    siacoin_outputs: vec![],
                    file_contracts: vec![],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![],
                    siafund_inputs: vec![],
                    siafund_outputs: vec![],
                    miner_fees: vec![],
                    arbitrary_data: vec![],
                    signatures: vec![],
                },
                "22d26fe3e660d58a26a7da864357c1930c3c24393dd5712d851e0c1c0a0706c2",
            ),
        ];

        for (i, (cf, expected)) in test_cases.iter().enumerate() {
            let sig_hash = txn.partial_sig_hash(&cs, cf).expect("valid sig hash");
            assert_eq!(sig_hash.to_string(), *expected, "case {i}")
        }
    }

    #[test]
    fn test_standard_unlockhash() {
        let test_cases = vec![
            (
                "80f637df83a93a6916d1b5c8bdbb061f967fb9fe8fe51ef4d97eeec73c6bfc394771e4a04f42",
                hex::decode("ad08d551ab7116b8c2285de81ffa528ef3679f9e242c3f551b560a60ab9763db")
                    .unwrap(),
            ),
            (
                "99a27a168bdde2e9c59bc967f6c662e3db0b2cf13da26ddae26004fa19c61d3db017dca7d0d3",
                hex::decode("18ac9c05b0c5e7c62859812b943572429cda178aa3df92697569b8984c603b4c")
                    .unwrap(),
            ),
            (
                "128151658b256d0185f3f91504758349a96e73c1a68a39c7ff7bf9d0e416997c964d773858ce",
                hex::decode("2b36cc860796f2e8a1990b437f46a4b905840e6ba41ba5f68fe2b8ebe23626af")
                    .unwrap(),
            ),
            (
                "1f47d453cfd7369bce4034d3ab461feb2a4d073bf59c959225993d00e38d71a8fea7c57cd3f1",
                hex::decode("a3e3c2f3493a079d3dfe69681bf878c59337e3d1c79d17a34e3da81f062bbe21")
                    .unwrap(),
            ),
            (
                "e03c56f8d95894cea875711e2f909c68c07dd37142a8253813ad09abceb2b6e5dd89992c9638",
                hex::decode("a03d3b27db7e143cb8b39a1eb9234bffad59d6f50adf4f0ee916afd510a939a0")
                    .unwrap(),
            ),
            (
                "68b6dd2e50f12e2deef2efd6b7baa660d87950ea16c5a8402a6db5873e062bcdd5246940b44e",
                hex::decode("52e4438ca9b6eb2d33953f97255e410130d55749432094fe9963f4fc65167ce5")
                    .unwrap(),
            ),
            (
                "c766e0a5ef49b7bab6c2e9c6a0b699e87eb3580e08f3fe77648dd93b66795a8606787cc5e29e",
                hex::decode("4110f8b0ade1cca7aa40008a9b9911655393288eaacc3948fecd13edd3f092ec")
                    .unwrap(),
            ),
            (
                "b455cf3c22de0d84ab8599499b0c2056d4916ab4c642b6b716148487f83ca5a85ad199b7a454",
                hex::decode("861d50c4ee90b0a6a5544a3820978dad1fd9391c4813ede9e4963f0d6bec010a")
                    .unwrap(),
            ),
            (
                "5274e9f3db1acfe8bb2d67dbbb5b6f2cc20769a0b42c8a9187ae827bf637f06e62ecada30f9f",
                hex::decode("a5329c135951f3505d9a26d2833cb6c1aebb875fbada80f38b09bd3314f26802")
                    .unwrap(),
            ),
            (
                "1540f42840b0479b238ec0143984a784c58240a8ca5e21da4b66be89a2f54353c99739938947",
                hex::decode("e11589e1857b7a0d2fc3526fbdfdc4d4708dfbf251184be1118138df4ef2d47e")
                    .unwrap(),
            ),
            (
                "21592f041e6f6861f199d54a26fe6bdfc5d629bb5dda12058d3ce28549c4aeffdbbdb67c2b95",
                hex::decode("d57887af5b838ea2d20a582f659b3e36ca47d33b253364e3b774a1f4feb8415b")
                    .unwrap(),
            ),
            (
                "f34b1e0b74a695f8bc82a97bab3b9d1ebe420956cbb3f7611c349c9659ba13fa362a417b1fd2",
                hex::decode("5da4058d2f95e3c547aab8b5c70817ed3795856aa7988676f266cb429d75ce06")
                    .unwrap(),
            ),
            (
                "3549a1680fcc093347e2674f4e89c84200965e1b779e2b3c05e4b21645a0b2fd5ac86923ef7a",
                hex::decode("98ced26430f3be35b29ca76d3f65ea616f89e2510a3c1307856522e23057d958")
                    .unwrap(),
            ),
            (
                "86fc291f7f53def33f2f7566f5ff08763bf5ada158f97c87fc240d1dcb04aa2a7b289018e33e",
                hex::decode("e715d5dc3bd8edecb453c59f85998591d7c14fd08057a0605cb416f6751eaad9")
                    .unwrap(),
            ),
            (
                "46e60abc3acbff858e382783f0739a8b2f2ba4c51b26941d979e60cb5292f11df1112b7016c0",
                hex::decode("359eee8d1ef18ed647bbd63cb4b2be85061f8e3fd67318e13924ddbc1beb815f")
                    .unwrap(),
            ),
            (
                "015b4b0759b0adee6c01de051bdacefe1f30eb571c83fa6c37607008696a9fa7f85273061e72",
                hex::decode("cf5cd07f31ca3aa3b7d2947da7e92c42ec5f981eff80ff1b438e59fd456465fb")
                    .unwrap(),
            ),
            (
                "7435604655772ca5ff011127c83692e40945187954da3bc7c01102d59701c7351aadbdc9ac8b",
                hex::decode("7f6a73aeb6de28f1d3935941caa8cab286d13d8c74f2352b5b717c3d743db9c1")
                    .unwrap(),
            ),
            (
                "c554d56a2eaffd8426006fb6d987cc615fb4ec05b1b15e793ab9d9127d79cf323787817467e6",
                hex::decode("14b98855c4f22295fcf3e2ec5d5fdfbb877979639c963bf6e226a0fb71902baf")
                    .unwrap(),
            ),
            (
                "c4850dbcddb9dfac6f44007ec58fe824bc58e3de2432de478f3e53f7965c2afd7ea651b6c2bf",
                hex::decode("6f5c23f8797f93d3d3c689fe1a3f5d9a1fbf326a7a6ea51fecbeaa9aba46f180")
                    .unwrap(),
            ),
            (
                "6a8f4f1d5a7405aa24cb1fb2a3c1dcaae74175c712002627289b5cd9dd887088afe605460abd",
                hex::decode("45f12760f6005a93cece248f5ec78adf15f9d29dafe397c8c28fefc72781d6fb")
                    .unwrap(),
            ),
            (
                "e464b9b1c9282d8edeed5832b95405761db6dacf6a156fc9119a396bdc8f8892815c7dce20fd",
                hex::decode("1c12d17a2a8b2c25950872f312d5d0758f07d8357c98897fc472565a44b3d1f1")
                    .unwrap(),
            ),
            (
                "9ae839af434aa13de6e8baa280541716811dcbaa33165fea5e9bad0c33998c10f16fcac4f214",
                hex::decode("686d28bf7e4b4cadf759994caed1e52092e12c11cef257a265b50402dbd70c3b")
                    .unwrap(),
            ),
            (
                "e92722d80103af9574f19a6cf72aab424335927eb7da022455f53314e3587dc8ece40d254981",
                hex::decode("b2e9ddef40897219a997ae7af277a5550cc10c54e793b6d2146de94df3bd552b")
                    .unwrap(),
            ),
            (
                "e2a02510f242f35e46b8840d8da42c087ea906b09d8e454c734663650236977da0362dd2ab43",
                hex::decode("4f756e475a706cdcec8eb1c02b21a591e0c0450cc0408ae8aec82ae97f634ecf")
                    .unwrap(),
            ),
            (
                "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0",
                hex::decode("cd46b523d2ee92f205a00726d8544094bb4fe58142ecffd20ea32b37b6e6bfc3")
                    .unwrap(),
            ),
        ];

        for (expected_str, public_key) in test_cases {
            let expected = Address::parse_string(expected_str).unwrap();

            let public_key = PublicKey::new(public_key.as_slice().try_into().unwrap());
            let addr = UnlockConditions::standard_unlock_conditions(public_key).address();

            assert_eq!(addr, expected);
            // test string round-trip
            if !expected_str.starts_with("") {
                assert_eq!(addr.to_string(), "".to_string() + expected_str)
            } else {
                assert_eq!(addr.to_string(), expected_str)
            }
        }
    }

    #[test]
    fn test_seed_standard_unlock_hash() {
        const PHRASE: &str =
            "song renew capable taxi follow sword more hybrid laptop dance unfair poem";
        let test_addresses = vec![
            (
                0,
                address!(
                    "16e09f8dc8a100a03ba1f9503e4035661738d1bea0b6cdc9bb012d3cd25edaacfd780909e550"
                ),
            ),
            (
                1,
                address!(
                    "cb016a7018485325fa299bc247113e3792dbea27ee08d2bb57a16cb0804fa449d3a91ee647a1"
                ),
            ),
            (
                2,
                address!(
                    "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34"
                ),
            ),
            (
                3,
                address!(
                    "c3bc7bc1431460ed2556874cb63714760120125da758ebbd78198534cb3d25774352fdbb3e8b"
                ),
            ),
            (
                4,
                address!(
                    "ebc7eae02ecf76e3ba7312bab6b6f71e9d255801a3a3b83f7cc26bd520b2c27a511cd8604e4b"
                ),
            ),
            (
                5,
                address!(
                    "fce241a44b944b10f414782dd35f5d96b92aec3d6da92a45ae44b7dc8cfb4b4ba97a34ce7032"
                ),
            ),
            (
                6,
                address!(
                    "36d253e7c3af2213eccaf0a61c6d24be8668f72af6e773463f3c41efc8bb70f2b353b90de9dd"
                ),
            ),
            (
                7,
                address!(
                    "c8f85375fb264428c86594863440f856db1da4614d75f4a30e3d9db3dfc88af6995128c6a845"
                ),
            ),
            (
                8,
                address!(
                    "85ef2ba14ee464060570b16bddaac91353961e7545067ccdf868a0ece305f00d2c08ec6844c6"
                ),
            ),
            (
                9,
                address!(
                    "9dcf644245eba91e7ea70c47ccadf479e6834c1c1221335e7246e0a6bc40e18362c4faa760b8"
                ),
            ),
            (
                4294967295,
                address!(
                    "a906891f0c524fd272a905aa5dd7018c69e5d68222385cbd9d5292f38f021ce4bf00953a0659"
                ),
            ),
            (
                4294967296,
                address!(
                    "b6ab338e624a304add7afe205361ac71821b87559a3b9c5b3735eaafa914eed533613a0af7fa"
                ),
            ),
            (
                18446744073709551615,
                address!(
                    "832d0e8b5f967677d812d75559c373d930ad16eb90c31c29982a190bb7db9edf9438fd827938"
                ),
            ),
        ];

        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        for (i, expected) in test_addresses {
            let pk = seed.private_key(i).public_key();
            let addr: Address = UnlockConditions::standard_unlock_conditions(pk).address();

            assert_eq!(addr, expected, "index {i}");
        }
    }

    #[test]
    fn test_file_contract_tax() {
        struct TestCase {
            payout: Currency,
            prefork: Currency,
            postfork: Currency,
        }
        let test_cases = vec![
            TestCase {
                payout: Currency::new(0),
                prefork: Currency::new(0),
                postfork: Currency::new(0),
            },
            TestCase {
                payout: Currency::new(1),
                prefork: Currency::new(0),
                postfork: Currency::new(0),
            },
            TestCase {
                payout: Currency::new(2),
                prefork: Currency::new(0),
                postfork: Currency::new(0),
            },
            TestCase {
                payout: Currency::new(340282366920938463463374607431768211455),
                prefork: Currency::new(13271012309916600075071609689838960000),
                postfork: Currency::new(13271012309916600075071609689838960000),
            },
            TestCase {
                payout: Currency::new(595540520000000000000000000000000),
                prefork: Currency::new(23226080280000000000000000000000),
                postfork: Currency::new(23226080280000000000000000000000),
            },
            TestCase {
                payout: Currency::new(103983762872653413852682180916164570605),
                prefork: Currency::new(4055366752033483140254605055730410000),
                postfork: Currency::new(4055366752033483140254605055730410000),
            },
            TestCase {
                payout: Currency::new(3827764528000000000000000000000000),
                prefork: Currency::new(149282816592000000000000000000000),
                postfork: Currency::new(149282816592000000000000000000000),
            },
            TestCase {
                payout: Currency::new(216196544861605368913933682930139323360),
                prefork: Currency::new(8431665249602609387643413634275430000),
                postfork: Currency::new(8431665249602609387643413634275430000),
            },
            TestCase {
                payout: Currency::new(2630651610000000000000000000000000),
                prefork: Currency::new(102595412790000000000000000000000),
                postfork: Currency::new(102595412790000000000000000000000),
            },
            TestCase {
                payout: Currency::new(242035606817835258338180817515298863866),
                prefork: Currency::new(9439388665895575075189051883096650000),
                postfork: Currency::new(9439388665895575075189051883096650000),
            },
            TestCase {
                payout: Currency::new(3830155529000000000000000000000000),
                prefork: Currency::new(149376065631000000000000000000000),
                postfork: Currency::new(149376065631000000000000000000000),
            },
            TestCase {
                payout: Currency::new(126852058180828682198189558142776852406),
                prefork: Currency::new(4947230269052318605729392767568290000),
                postfork: Currency::new(4947230269052318605729392767568290000),
            },
            TestCase {
                payout: Currency::new(3497644816000000000000000000000000),
                prefork: Currency::new(136408147824000000000000000000000),
                postfork: Currency::new(136408147824000000000000000000000),
            },
            TestCase {
                payout: Currency::new(202288428857506739014982837533616200189),
                prefork: Currency::new(7889248725442762821584330663811030000),
                postfork: Currency::new(7889248725442762821584330663811030000),
            },
            TestCase {
                payout: Currency::new(3717108920000000000000000000000000),
                prefork: Currency::new(144967247880000000000000000000000),
                postfork: Currency::new(144967247880000000000000000000000),
            },
            TestCase {
                payout: Currency::new(319915558118289110319073160920214552278),
                prefork: Currency::new(12476706766613275302443853275888360000),
                postfork: Currency::new(12476706766613275302443853275888360000),
            },
            TestCase {
                payout: Currency::new(2205536583000000000000000000000000),
                prefork: Currency::new(86015926737000000000000000000000),
                postfork: Currency::new(86015926737000000000000000000000),
            },
            TestCase {
                payout: Currency::new(138040906509763116024244911687441931808),
                prefork: Currency::new(5383595353880761524945551555810230000),
                postfork: Currency::new(5383595353880761524945551555810230000),
            },
            TestCase {
                payout: Currency::new(1110927021000000000000000000000000),
                prefork: Currency::new(43326153819000000000000000000000),
                postfork: Currency::new(43326153819000000000000000000000),
            },
            TestCase {
                payout: Currency::new(215175656237682186102553629801543673418),
                prefork: Currency::new(8391850593269605257999591562260200000),
                postfork: Currency::new(8391850593269605257999591562260200000),
            },
            TestCase {
                payout: Currency::new(646634091000000000000000000000000),
                prefork: Currency::new(25218729549000000000000000000000),
                postfork: Currency::new(25218729549000000000000000000000),
            },
            TestCase {
                payout: Currency::new(128469923315667767051668090462322677166),
                prefork: Currency::new(5010327009311042915015055528030580000),
                postfork: Currency::new(5010327009311042915015055528030580000),
            },
            TestCase {
                payout: Currency::new(2889549915000000000000000000000000),
                prefork: Currency::new(112692446685000000000000000000000),
                postfork: Currency::new(112692446685000000000000000000000),
            },
            TestCase {
                payout: Currency::new(269364173205837265395254441592734706401),
                prefork: Currency::new(10505202755027653350414923222116650000),
                postfork: Currency::new(10505202755027653350414923222116650000),
            },
        ];

        let mut cs = ChainState {
            state: State {
                index: ChainIndex {
                    height: 1,
                    id: BlockID::default(),
                },
                prev_timestamps: [OffsetDateTime::UNIX_EPOCH; 11],
                depth: BlockID::default(),
                child_target: BlockID::default(),
                siafund_pool: Currency::new(0),
                oak_time: Duration::new(0, 0),
                oak_target: BlockID::default(),
                foundation_primary_address: Address::new([0u8; 32]),
                foundation_failsafe_address: Address::new([0u8; 32]),
                total_work: Work::zero(),
                difficulty: Work::zero(),
                oak_work: Work::zero(),
                attestations: 0,
                elements: ElementAccumulator::default(),
            },
            network: Network {
                name: "test".to_string(),
                initial_coinbase: Currency::new(0),
                minimum_coinbase: Currency::new(0),
                initial_target: BlockID::default(),
                block_interval: Duration::new(1, 0),
                maturity_delay: 0,
                hardfork_dev_addr: HardforkDevAddr {
                    height: 0,
                    old_address: Address::new([0u8; 32]),
                    new_address: Address::new([0u8; 32]),
                },
                hardfork_tax: HardforkTax { height: 10 },
                hardfork_storage_proof: HardforkStorageProof { height: 0 },
                hardfork_asic: HardforkASIC {
                    height: 0,
                    oak_time: Duration::new(0, 0),
                    oak_target: BlockID::default(),
                },
                hardfork_oak: HardforkOak {
                    height: 0,
                    fix_height: 0,
                    genesis_timestamp: OffsetDateTime::UNIX_EPOCH,
                },
                hardfork_foundation: HardforkFoundation {
                    height: 0,
                    primary_address: Address::new([0u8; 32]),
                    failsafe_address: Address::new([0u8; 32]),
                },
                hardfork_v2: HardforkV2 {
                    allow_height: 0,
                    require_height: 0,
                },
            },
        };

        for tc in test_cases.iter() {
            let fc = FileContract {
                payout: tc.payout,
                file_size: 0,
                file_merkle_root: Hash256::default(),
                window_start: 0,
                window_end: 0,
                unlock_hash: Address::new([0u8; 32]),
                revision_number: 0,
                valid_proof_outputs: vec![],
                missed_proof_outputs: vec![],
            };

            let tax = fc.tax(&cs);
            assert_eq!(
                tax, tc.prefork,
                "prefork tax incorrect for payout {:?}",
                tc.payout
            );
            cs.state.index.height = 11;
            let tax = fc.tax(&cs);
            assert_eq!(
                tax, tc.postfork,
                "postfork tax incorrect for payout {:?}",
                tc.payout
            );
        }
    }
}
