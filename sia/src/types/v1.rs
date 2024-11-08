use core::fmt;

use blake2b_simd::Params;
use serde::de::Error;
use serde::{Deserialize, Serialize};

use crate::encoding::{
    self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode,
    V1SiaEncodable, V1SiaEncode,
};
use crate::merkle::{Accumulator, LEAF_HASH_PREFIX};
use crate::signing::{PrivateKey, PublicKey, SigningState};
use crate::types::{specifier, Specifier};

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
#[derive(Debug, PartialEq, Clone, SiaEncode, V1SiaEncode, SiaDecode, V1SiaDecode)]
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
            UnlockKey::parse_string(&s).map_err(|e| Error::custom(format!("{:?}", e)))
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
    Debug, PartialEq, Clone, Serialize, Deserialize, SiaEncode, SiaDecode, V1SiaEncode, V1SiaDecode,
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
    pub unlock_hash: Hash256,
    pub revision_number: u64,
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
    pub unlock_hash: Hash256,
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
    pub siacoin_inputs: Vec<usize>,
    pub siacoin_outputs: Vec<usize>,
    pub file_contracts: Vec<usize>,
    pub file_contract_revisions: Vec<usize>,
    pub storage_proofs: Vec<usize>,
    pub siafund_inputs: Vec<usize>,
    pub siafund_outputs: Vec<usize>,
    pub miner_fees: Vec<usize>,
    pub arbitrary_data: Vec<usize>,
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
    #[serde(with = "base64")]
    pub signature: Vec<u8>,
}

/// Helper module for base64 serialization
mod base64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = STANDARD.encode(v);
        s.serialize_str(&base64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        STANDARD
            .decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub siacoin_inputs: Vec<SiacoinInput>,
    pub siacoin_outputs: Vec<SiacoinOutput>,
    pub file_contracts: Vec<FileContract>,
    pub file_contract_revisions: Vec<FileContractRevision>,
    pub storage_proofs: Vec<StorageProof>,
    pub siafund_inputs: Vec<SiafundInput>,
    pub siafund_outputs: Vec<SiafundOutput>,
    pub miner_fees: Vec<Currency>,
    pub arbitrary_data: Vec<Vec<u8>>,
    pub signatures: Vec<TransactionSignature>,
}

impl Transaction {
    const SIACOIN_OUTPUT_ID_PREFIX: Specifier = specifier!("siacoin output");
    const SIAFUND_OUTPUT_ID_PREFIX: Specifier = specifier!("siafund output");

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

    pub(crate) fn whole_sig_hash(
        &self,
        chain: &SigningState,
        parent_id: &Hash256,
        public_key_index: u64,
        timelock: u64,
        covered_sigs: &Vec<usize>,
    ) -> Result<Hash256, encoding::Error> {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(&(self.siacoin_inputs.len() as u64).to_le_bytes());
        for input in self.siacoin_inputs.iter() {
            state.update(chain.replay_prefix());
            input.encode_v1(&mut state)?;
        }

        self.siacoin_outputs.encode_v1(&mut state)?;
        self.file_contracts.encode_v1(&mut state)?;
        self.file_contract_revisions.encode_v1(&mut state)?;
        self.storage_proofs.encode_v1(&mut state)?;

        state.update(&(self.siafund_inputs.len() as u64).to_le_bytes());
        for input in self.siafund_inputs.iter() {
            state.update(chain.replay_prefix());
            input.encode_v1(&mut state)?;
        }

        self.siafund_outputs.encode_v1(&mut state)?;
        self.miner_fees.encode_v1(&mut state)?;
        self.arbitrary_data.encode_v1(&mut state)?;

        parent_id.encode_v1(&mut state)?;
        public_key_index.encode_v1(&mut state)?;
        timelock.encode_v1(&mut state)?;

        for &i in covered_sigs {
            if i >= self.signatures.len() {
                return Err(encoding::Error::Custom(
                    "signatures index out of bounds".to_string(),
                ));
            }
            self.signatures[i].encode_v1(&mut state)?;
        }

        Ok(state.finalize().into())
    }

    pub(crate) fn partial_sig_hash(
        &self,
        chain: &SigningState,
        covered_fields: &CoveredFields,
    ) -> Result<Hash256, encoding::Error> {
        let mut state = Params::new().hash_length(32).to_state();

        for &i in covered_fields.siacoin_inputs.iter() {
            if i >= self.siacoin_inputs.len() {
                return Err(encoding::Error::Custom(
                    "siacoin_inputs index out of bounds".to_string(),
                ));
            }
            state.update(chain.replay_prefix());
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
            state.update(chain.replay_prefix());
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

    pub fn sign(
        &self,
        state: &SigningState,
        covered_fields: &CoveredFields,
        parent_id: Hash256,
        public_key_index: u64,
        timelock: u64,
        private_key: &PrivateKey,
    ) -> Result<TransactionSignature, encoding::Error> {
        let sig_hash = if covered_fields.whole_transaction {
            self.whole_sig_hash(
                state,
                &parent_id,
                public_key_index,
                timelock,
                &covered_fields.signatures,
            )
        } else {
            self.partial_sig_hash(state, covered_fields)
        }?;

        Ok(TransactionSignature {
            parent_id,
            public_key_index,
            timelock,
            covered_fields: covered_fields.clone(),
            signature: private_key.sign_hash(&sig_hash).data().to_vec(),
        })
    }

    pub fn id(&self) -> TransactionID {
        let mut state = Params::new().hash_length(32).to_state();
        self.encode_no_sigs(&mut state).unwrap();
        let hash = state.finalize();
        hash.into()
    }

    pub fn siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(Self::SIACOIN_OUTPUT_ID_PREFIX.as_bytes());
        self.encode_no_sigs(&mut state).unwrap();

        let h = state.update(&i.to_le_bytes()).finalize();
        SiacoinOutputID::from(h)
    }

    pub fn siafund_output_id(&self, i: usize) -> SiafundOutputID {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(Self::SIAFUND_OUTPUT_ID_PREFIX.as_bytes());
        self.encode_no_sigs(&mut state).unwrap();

        let h = state.update(&i.to_le_bytes()).finalize();
        SiafundOutputID::from(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;
    use crate::signing::{NetworkHardforks, PrivateKey, PublicKey, Signature};
    use crate::types::{BlockID, ChainIndex};
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;
    use std::vec;

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
            vec![PublicKey::new([
                0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47, 0xda,
                0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a, 0xd0, 0xdb,
                0x1d, 0x1c, 0xe1, 0xb6,
            ])
            .into()],
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
        assert_eq!(unlock_conditions_serialized, "{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1}");
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

        let json_str = "{\"wholeTransaction\":false,\"siacoinInputs\":[1],\"siacoinOutputs\":[2,3],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]}";
        test_serialize_json(&cf, json_str);
    }

    #[test]
    fn test_serialize_siacoin_input() {
        let siacoin_input = SiacoinInput {
            parent_id: SiacoinOutputID::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            unlock_conditions: UnlockConditions::new(
                123,
                vec![PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into()],
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
            parent_id: SiafundOutputID::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            unlock_conditions: UnlockConditions::new(
                123,
                vec![PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into()],
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
            parent_id: Hash256::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
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

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"publicKeyIndex\":1,\"timelock\":2,\"coveredFields\":{\"wholeTransaction\":true,\"siacoinInputs\":[],\"siacoinOutputs\":[],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]},\"signature\":\"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw==\"}";
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
            unlock_hash: Hash256::from([
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

        let json_str = "{\"filesize\":1,\"fileMerkleRoot\":\"0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"payout\":\"456\",\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"101112\",\"address\":\"0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"0404040000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":4}";
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
                vec![PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into()],
                1,
            ),
            unlock_hash: Hash256::from([
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

        let json_str = "{\"parentID\":\"0908070000000000000000000000000000000000000000000000000000000000\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"revisionNumber\":4,\"filesize\":1,\"fileMerkleRoot\":\"0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"789\",\"address\":\"0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"0404040000000000000000000000000000000000000000000000000000000000\"}";
        test_serialize_json(&revision, json_str);
    }

    #[test]
    fn test_serialize_storage_proof() {
        let storage_proof = StorageProof {
            parent_id: FileContractID::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            leaf: Leaf::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
            ]),
            proof: vec![
                Hash256::parse_string(
                    "0102030000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                Hash256::parse_string(
                    "0405060000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
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
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            file_contracts: Vec::new(),
            file_contract_revisions: Vec::new(),
            storage_proofs: Vec::new(),
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            miner_fees: Vec::new(),
            arbitrary_data: Vec::new(),
            signatures: Vec::new(),
        };
        let binary_str = hex::encode([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&transaction, binary_str.as_str());

        let json_str = "{\"siacoinInputs\":[],\"siacoinOutputs\":[],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]}";
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
    fn test_transaction_sign() {
        let state = SigningState {
            index: ChainIndex {
                height: 0,
                id: BlockID::default(),
            },
            median_timestamp: time::OffsetDateTime::now_utc(),
            hardforks: NetworkHardforks {
                asic_height: 0,
                foundation_height: 0,
                v2_allow_height: 1000,
                v2_require_height: 1000,
            },
        };
        let pk = PrivateKey::from_seed(&[
            136, 215, 58, 248, 45, 30, 78, 97, 128, 111, 82, 204, 43, 233, 223, 111, 110, 29, 73,
            157, 52, 25, 242, 96, 131, 16, 187, 22, 232, 107, 17, 205,
        ]);
        let test_cases = vec![
			(
				Transaction {
					siacoin_inputs: vec![
						SiacoinInput{
							parent_id: SiacoinOutputID::from([32,11,215,36,166,174,135,0,92,215,179,18,74,229,52,154,221,194,213,216,219,47,225,205,251,84,248,2,69,252,37,117]),
							unlock_conditions: UnlockConditions::standard_unlock_conditions(pk.public_key()),
						}
					],
					siacoin_outputs: vec![
						SiacoinOutput{
							value: Currency::new(67856467336433871),
							address: Address::parse_string("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
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
				"7a5db98318b5ecad2954d41ba2084c908823ebf4000b95543f352478066a0d04bf4829e3e6d086b42ff9d943f68981c479798fd42bf6f63dac254f4294a37609"
			)
		];

        for (txn, expected) in test_cases {
            let sig = txn
                .sign(
                    &state,
                    &CoveredFields::whole_transaction(),
                    Hash256::from(<SiacoinOutputID as Into<[u8; 32]>>::into(
                        txn.siacoin_inputs[0].parent_id,
                    )),
                    0,
                    0,
                    &pk,
                )
                .expect("");

            assert_eq!(hex::encode(sig.signature), expected)
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
                Address::parse_string(
                    "16e09f8dc8a100a03ba1f9503e4035661738d1bea0b6cdc9bb012d3cd25edaacfd780909e550",
                )
                .unwrap(),
            ),
            (
                1,
                Address::parse_string(
                    "cb016a7018485325fa299bc247113e3792dbea27ee08d2bb57a16cb0804fa449d3a91ee647a1",
                )
                .unwrap(),
            ),
            (
                2,
                Address::parse_string(
                    "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34",
                )
                .unwrap(),
            ),
            (
                3,
                Address::parse_string(
                    "c3bc7bc1431460ed2556874cb63714760120125da758ebbd78198534cb3d25774352fdbb3e8b",
                )
                .unwrap(),
            ),
            (
                4,
                Address::parse_string(
                    "ebc7eae02ecf76e3ba7312bab6b6f71e9d255801a3a3b83f7cc26bd520b2c27a511cd8604e4b",
                )
                .unwrap(),
            ),
            (
                5,
                Address::parse_string(
                    "fce241a44b944b10f414782dd35f5d96b92aec3d6da92a45ae44b7dc8cfb4b4ba97a34ce7032",
                )
                .unwrap(),
            ),
            (
                6,
                Address::parse_string(
                    "36d253e7c3af2213eccaf0a61c6d24be8668f72af6e773463f3c41efc8bb70f2b353b90de9dd",
                )
                .unwrap(),
            ),
            (
                7,
                Address::parse_string(
                    "c8f85375fb264428c86594863440f856db1da4614d75f4a30e3d9db3dfc88af6995128c6a845",
                )
                .unwrap(),
            ),
            (
                8,
                Address::parse_string(
                    "85ef2ba14ee464060570b16bddaac91353961e7545067ccdf868a0ece305f00d2c08ec6844c6",
                )
                .unwrap(),
            ),
            (
                9,
                Address::parse_string(
                    "9dcf644245eba91e7ea70c47ccadf479e6834c1c1221335e7246e0a6bc40e18362c4faa760b8",
                )
                .unwrap(),
            ),
            (
                4294967295,
                Address::parse_string(
                    "a906891f0c524fd272a905aa5dd7018c69e5d68222385cbd9d5292f38f021ce4bf00953a0659",
                )
                .unwrap(),
            ),
            (
                4294967296,
                Address::parse_string(
                    "b6ab338e624a304add7afe205361ac71821b87559a3b9c5b3735eaafa914eed533613a0af7fa",
                )
                .unwrap(),
            ),
            (
                18446744073709551615,
                Address::parse_string(
                    "832d0e8b5f967677d812d75559c373d930ad16eb90c31c29982a190bb7db9edf9438fd827938",
                )
                .unwrap(),
            ),
        ];

        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        for (i, expected) in test_addresses {
            let pk = seed.private_key(i).public_key();
            let addr: Address = UnlockConditions::standard_unlock_conditions(pk).address();

            assert_eq!(addr, expected, "index {}", i);
        }
    }
}
