use crate::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use serde::de::{Error, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::signing::{PublicKey, Signature};
use crate::types::common::BlockID;

use super::{
    Address, AttestationID, ChainIndex, Currency, FileContractID, Hash256, Leaf, SiacoinOutput,
    SiacoinOutputID, SiafundOutput, SiafundOutputID, StateElement,
};

// expose spend policies
pub use super::spendpolicy::*;

/// An Attestation associates a key-value pair with an identity. For example,
/// hosts attest to their network address by setting Key to "HostAnnouncement"
/// and Value to their address, thereby allowing renters to discover them.
/// Generally, an attestation for a particular key is considered to overwrite any
/// previous attestations with the same key. (This allows hosts to announce a new
/// network address, for example.)
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub public_key: PublicKey,
    pub key: String,
    pub value: Vec<u8>,

    pub signature: Signature,
}

/// A FileContract is a storage agreement between a renter and a host. It
/// consists of a bidirectional payment channel that resolves as either "valid"
/// or "missed" depending on whether a valid StorageProof is submitted for the
/// contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContract {
    pub capacity: u64,
    pub filesize: u64,
    pub file_merkle_root: Hash256,
    pub proof_height: u64,
    pub expiration_height: u64,
    pub renter_output: SiacoinOutput,
    pub host_output: SiacoinOutput,
    pub missed_host_value: Currency,
    pub total_collateral: Currency,
    pub renter_public_key: PublicKey,
    pub host_public_key: PublicKey,
    pub revision_number: u64,

    pub renter_signature: Signature,
    pub host_signature: Signature,
}

/// A SiacoinElement is a record of a Siacoin UTXO within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinElement {
    pub state_element: StateElement,
    pub id: SiacoinOutputID,
    pub siacoin_output: SiacoinOutput,
    pub maturity_height: u64,
}

/// A SiafundElement is a record of a Siafund UTXO within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundElement {
    pub state_element: StateElement,
    pub id: SiafundOutputID,
    pub siafund_output: SiafundOutput,
    pub claim_start: Currency,
}

/// A V2FileContractElement is a record of a FileContract within the state
/// accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractElement {
    pub state_element: StateElement,
    pub id: FileContractID,
    pub v2_file_contract: FileContract,
}

/// A ChainIndexElement is a record of a ChainIndex within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct ChainIndexElement {
    pub state_element: StateElement,
    pub id: BlockID,
    pub chain_index: ChainIndex,
}

/// An AttestationElement is a record of an Attestation within the state
/// accumulator.
pub struct AttestationElement {
    pub state_element: StateElement,
    pub id: AttestationID,
    pub attestation: Attestation,
}

/// A V2SiacoinInput represents a Siacoin UTXO that is being spent in a v2
/// transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInput {
    pub parent: SiacoinElement,
    pub satisfied_policy: SatisfiedPolicy,
}

/// A V2SiafundInput represents a Siafund UTXO that is being spent in a v2
/// transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInput {
    pub parent: SiafundElement,
    pub claim_address: Address,
    pub satisfied_policy: SatisfiedPolicy,
}

/// A FileContractRevision updates the state of an existing file contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractRevision {
    pub parent: FileContractElement,
    pub revision: FileContract,
}

/// A FileContractRenewal renews a file contract with optional rollover
/// of any unspent funds.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractRenewal {
    pub final_revision: FileContract,
    pub new_contract: FileContract,
    pub renter_rollover: Currency,
    pub host_rollover: Currency,

    // signatures cover above fields
    pub renter_signature: Signature,
    pub host_signature: Signature,
}

/// A StorageProof asserts the presence of a randomly-selected leaf within the
/// Merkle tree of a V2FileContract's data.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    // Selecting the leaf requires a source of unpredictable entropy; we use the
    // ID of the block at the contract's ProofHeight. The storage proof thus
    // includes a proof that this ID is the correct ancestor.
    //
    // During validation, it is imperative to check that ProofIndex.Height
    // matches the ProofHeight field of the contract's final revision;
    // otherwise, the prover could use any ProofIndex, giving them control over
    // the leaf index.
    pub proof_index: ChainIndexElement,
    // The leaf is always 64 bytes, extended with zeros if necessary.
    pub leaf: Leaf,
    pub proof: Vec<Hash256>,
}

// A ContractResolution closes a v2 file contract's payment channel. There
/// are four ways a contract can be resolved:
///
/// 1. The renter can finalize the contract's current state, preventing further
///     revisions and immediately creating its outputs.
///
/// 2. The renter and host can jointly renew the contract. The old contract is
///     finalized, and a portion of its funds are "rolled over" into a new contract.
///
/// 3. The host can submit a storage proof, asserting that it has faithfully
///     stored the contract data for the agreed-upon duration. Typically, a storage
///     proof is only required if the renter is unable or unwilling to sign a
///     finalization or renewal. A storage proof can only be submitted after the
///     contract's ProofHeight; this allows the renter (or host) to broadcast the
///     latest contract revision prior to the proof.
///
/// 4. Lastly, anyone can submit a contract expiration. Typically, an expiration
///     is only required if the host is unable or unwilling to sign a finalization or
///     renewal. An expiration can only be submitted after the contract's
///     ExpirationHeight; this gives the host a reasonable window of time after the
///     ProofHeight in which to submit a storage proof.
///
/// Once a contract has been resolved, it cannot be altered or resolved again.
/// When a contract is resolved, its RenterOutput and HostOutput are created
/// immediately (though they will not be spendable until their timelock expires).
/// However, if the contract is resolved via an expiration, the HostOutput will
/// have value equal to MissedHostValue; in other words, the host forfeits its
/// collateral. This is considered a "missed" resolution; all other resolution
/// types are "valid." As a special case, the expiration of an empty contract is
/// considered valid, reflecting the fact that the host has not failed to perform
/// any duty.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum ContractResolution {
    Finalization(Signature),
    Renewal(FileContractRenewal),
    StorageProof(StorageProof),
    Expiration(),
}

/// A FileContractResolution closes a v2 file contract's payment channel.
#[derive(Debug, PartialEq)]
pub struct FileContractResolution {
    pub parent: FileContractElement,
    pub resolution: ContractResolution,
}

impl SiaEncodable for FileContractResolution {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent.encode(w)?;
        match &self.resolution {
            ContractResolution::Renewal(renewal) => {
                0u8.encode(w)?;
                renewal.encode(w)
            }
            ContractResolution::StorageProof(proof) => {
                1u8.encode(w)?;
                proof.encode(w)
            }
            ContractResolution::Finalization(sig) => {
                2u8.encode(w)?;
                sig.encode(w)
            }
            ContractResolution::Expiration() => 3u8.encode(w),
        }
    }
}

impl SiaDecodable for FileContractResolution {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let parent = FileContractElement::decode(r)?;
        let resolution = match u8::decode(r)? {
            0 => ContractResolution::Renewal(FileContractRenewal::decode(r)?),
            1 => ContractResolution::StorageProof(StorageProof::decode(r)?),
            2 => ContractResolution::Finalization(Signature::decode(r)?),
            3 => ContractResolution::Expiration(),
            _ => {
                return Err(encoding::Error::Custom(
                    "invalid contract resolution type".to_string(),
                ))
            }
        };
        Ok(FileContractResolution { parent, resolution })
    }
}

impl Serialize for FileContractResolution {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("FileContractResolution", 3)?;
        state.serialize_field("parent", &self.parent)?;
        state.serialize_field(
            "type",
            &match &self.resolution {
                ContractResolution::Renewal(_) => "renewal",
                ContractResolution::StorageProof(_) => "storageProof",
                ContractResolution::Finalization(_) => "finalization",
                ContractResolution::Expiration() => "expiration",
            },
        )?;
        let resolution = match &self.resolution {
            ContractResolution::Finalization(sig) => {
                serde_json::to_value(sig).map_err(serde::ser::Error::custom)?
            }
            ContractResolution::Renewal(renewal) => {
                serde_json::to_value(renewal).map_err(serde::ser::Error::custom)?
            }
            ContractResolution::StorageProof(proof) => {
                serde_json::to_value(proof).map_err(serde::ser::Error::custom)?
            }
            ContractResolution::Expiration() => json!({}),
        };
        state.serialize_field("resolution", &resolution)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for FileContractResolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FileContractResolutionVisitor;

        impl<'de> Visitor<'de> for FileContractResolutionVisitor {
            type Value = FileContractResolution;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct FileContractResolution")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut parent: Option<FileContractElement> = None;
                let mut resolution_type: Option<String> = None;
                let mut resolution_value: Option<serde_json::Value> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "parent" => parent = Some(map.next_value()?),
                        "type" => resolution_type = Some(map.next_value()?),
                        "resolution" => resolution_value = Some(map.next_value()?),
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key.as_str(),
                                &["parent", "type", "resolution"],
                            ));
                        }
                    }
                }

                let parent = parent.ok_or_else(|| serde::de::Error::missing_field("parent"))?;
                let resolution_type =
                    resolution_type.ok_or_else(|| serde::de::Error::missing_field("type"))?;
                let resolution_value = resolution_value
                    .ok_or_else(|| serde::de::Error::missing_field("resolution"))?;

                let resolution = match resolution_type.as_str() {
                    "finalization" => ContractResolution::Finalization(
                        serde_json::from_value(resolution_value).map_err(Error::custom)?,
                    ),
                    "renewal" => ContractResolution::Renewal(
                        serde_json::from_value(resolution_value).map_err(Error::custom)?,
                    ),
                    "storageProof" => ContractResolution::StorageProof(
                        serde_json::from_value(resolution_value).map_err(Error::custom)?,
                    ),
                    "expiration" => ContractResolution::Expiration(),
                    _ => return Err(serde::de::Error::custom("invalid contract resolution type")),
                };

                Ok(FileContractResolution { parent, resolution })
            }
        }
        deserializer.deserialize_struct(
            "FileContractResolution",
            &["parent", "type", "resolution"],
            FileContractResolutionVisitor,
        )
    }
}

/// A Transaction effects a change of blockchain state.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub siacoin_inputs: Vec<SiacoinInput>,
    pub siacoin_outputs: Vec<SiacoinOutput>,
    pub siafund_inputs: Vec<SiafundInput>,
    pub siafund_outputs: Vec<SiafundOutput>,
    pub file_contracts: Vec<FileContractElement>,
    pub file_contract_revisions: Vec<FileContractRevision>,
    pub file_contract_resolutions: Vec<FileContractResolution>,
    pub arbitrary_data: Vec<Vec<u8>>,
    pub new_foundation_address: Option<Address>,
    pub miner_fee: Currency,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Debug;
    use serde::de::DeserializeOwned;
    use serde::Serialize;

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

    /// test_serialize is a helper to test serialization and deserialization of a struct to and from Sia's
    /// custom binary encoding.
    fn test_serialize<S: SiaEncodable + SiaDecodable + Debug + PartialEq>(
        obj: &S,
        hex_binary: &str,
    ) {
        let mut serialized = Vec::new();
        obj.encode(&mut serialized).unwrap();
        assert_eq!(hex::encode(serialized.clone()), hex_binary);
        let deserialized = S::decode(&mut &serialized[..]).unwrap();
        assert_eq!(deserialized, *obj);
    }

    #[test]
    fn test_serialize_siacoin_element() {
        let se = SiacoinElement {
            id: SiacoinOutputID::default(),
            siacoin_output: SiacoinOutput {
                value: Currency::new(2389084800000000000000000000000000),
                address: Address::new([0; 32]),
            },
            state_element: StateElement {
                leaf_index: 0,
                merkle_proof: vec![Hash256::default()],
            },
            maturity_height: 0,
        };

        let binary_str = "0000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000809ab5dad71c4e547dca75000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&se, binary_str);

        let json_str = "{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"siacoinOutput\":{\"value\":\"2389084800000000000000000000000000\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"maturityHeight\":0}";
        test_serialize_json(&se, json_str);
    }

    #[test]
    fn test_serialize_siafund_element() {
        let se = SiafundElement {
            id: SiafundOutputID::default(),
            state_element: StateElement {
                leaf_index: 0,
                merkle_proof: vec![Hash256::default()],
            },
            siafund_output: SiafundOutput {
                value: 1086708929188041408,
                address: Address::new([0; 32]),
            },
            claim_start: Currency::new(0),
        };

        let binary_str = "0000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0927f7203c4140f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&se, binary_str);

        let json_str = "{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"siafundOutput\":{\"value\":1086708929188041408,\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"claimStart\":\"0\"}";
        test_serialize_json(&se, json_str);
    }

    #[test]
    fn test_serialize_file_contract_element() {
        let fce = FileContractElement {
            id: FileContractID::default(),
            state_element: StateElement {
                leaf_index: 0,
                merkle_proof: vec![Hash256::default()],
            },
            v2_file_contract: FileContract {
                capacity: 7938725446189123975,
                filesize: 4815560028289493432,
                file_merkle_root: Hash256::parse_string(
                    "dc033023420634ed4c7685c82aa884eebe8415e16c57b6a55c673a5a98fa7b0d",
                )
                .unwrap(),
                proof_height: 6265010746208955018,
                expiration_height: 5159880069065321628,
                renter_output: SiacoinOutput {
                    value: Currency::new(3837391090000000000000000000000000),
                    address: Address::new([0; 32]),
                },
                host_output: SiacoinOutput {
                    value: Currency::new(3827725744000000000000000000000000),
                    address: Address::new([0; 32]),
                },
                missed_host_value: Currency::new(965900695000000000000000000000000),
                total_collateral: Currency::new(0),
                host_public_key: PublicKey::new([0; 32]),
                renter_public_key: PublicKey::new([0; 32]),
                revision_number: 0,

                host_signature: Signature::new([0; 64]),
                renter_signature: Signature::new([0; 64]),
            },
        };

        let binary_str = "00000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008709756dbb042c6eb8e9c3f0544ed442dc033023420634ed4c7685c82aa884eebe8415e16c57b6a55c673a5a98fa7b0d8a2aca8914caf1569cac41a895939b470000003292d8b9e4856e58af32bd00000000000000000000000000000000000000000000000000000000000000000000000000b0f3637fb05e9bedb0b8bc00000000000000000000000000000000000000000000000000000000000000000000000000f7420336ee348e78619f2f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&fce, binary_str);

        let json_str = "{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"v2FileContract\":{\"capacity\":7938725446189123975,\"filesize\":4815560028289493432,\"fileMerkleRoot\":\"dc033023420634ed4c7685c82aa884eebe8415e16c57b6a55c673a5a98fa7b0d\",\"proofHeight\":6265010746208955018,\"expirationHeight\":5159880069065321628,\"renterOutput\":{\"value\":\"3837391090000000000000000000000000\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"3827725744000000000000000000000000\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"965900695000000000000000000000000\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}}";
        test_serialize_json(&fce, json_str);
    }

    #[test]
    fn test_serialize_file_contract() {
        let fc = FileContract {
            capacity: 0,
            filesize: 0,
            file_merkle_root: Hash256::default(),
            proof_height: 0,
            expiration_height: 0,
            renter_output: SiacoinOutput {
                value: Currency::new(0),
                address: Address::new([0; 32]),
            },
            host_output: SiacoinOutput {
                value: Currency::new(0),
                address: Address::new([0; 32]),
            },
            missed_host_value: Currency::new(0),
            total_collateral: Currency::new(0),
            host_public_key: PublicKey::new([0; 32]),
            renter_public_key: PublicKey::new([0; 32]),
            revision_number: 0,

            host_signature: Signature::new([0; 64]),
            renter_signature: Signature::new([0; 64]),
        };

        let binary_str = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&fc, binary_str);

        let json_str = "{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}";
        test_serialize_json(&fc, json_str);
    }

    #[test]
    fn test_serialize_file_contract_revision() {
        let fcr = FileContractRevision {
            parent: FileContractElement {
                id: FileContractID::default(),
                state_element: StateElement {
                    leaf_index: 0,
                    merkle_proof: vec![Hash256::default()],
                },
                v2_file_contract: FileContract {
                    capacity: 0,
                    filesize: 0,
                    file_merkle_root: Hash256::default(),
                    proof_height: 0,
                    expiration_height: 0,
                    renter_output: SiacoinOutput {
                        value: Currency::new(0),
                        address: Address::new([0; 32]),
                    },
                    host_output: SiacoinOutput {
                        value: Currency::new(0),
                        address: Address::new([0; 32]),
                    },
                    missed_host_value: Currency::new(0),
                    total_collateral: Currency::new(0),
                    host_public_key: PublicKey::new([0; 32]),
                    renter_public_key: PublicKey::new([0; 32]),
                    revision_number: 0,

                    host_signature: Signature::new([0; 64]),
                    renter_signature: Signature::new([0; 64]),
                },
            },
            revision: FileContract {
                capacity: 0,
                filesize: 0,
                file_merkle_root: Hash256::default(),
                proof_height: 0,
                expiration_height: 0,
                renter_output: SiacoinOutput {
                    value: Currency::new(0),
                    address: Address::new([0; 32]),
                },
                host_output: SiacoinOutput {
                    value: Currency::new(0),
                    address: Address::new([0; 32]),
                },
                missed_host_value: Currency::new(0),
                total_collateral: Currency::new(0),
                host_public_key: PublicKey::new([0; 32]),
                renter_public_key: PublicKey::new([0; 32]),
                revision_number: 0,

                host_signature: Signature::new([0; 64]),
                renter_signature: Signature::new([0; 64]),
            },
        };

        let binary_str = "000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&fcr, binary_str);

        let json_str = "{\"parent\":{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"v2FileContract\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}},\"revision\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}}";
        test_serialize_json(&fcr, json_str);
    }

    #[test]
    fn test_serialize_file_contract_renewal() {
        let fcr = FileContractRenewal {
            new_contract: FileContract {
                capacity: 0,
                filesize: 0,
                file_merkle_root: Hash256::default(),
                proof_height: 0,
                expiration_height: 0,
                renter_output: SiacoinOutput {
                    value: Currency::new(0),
                    address: Address::new([0; 32]),
                },
                host_output: SiacoinOutput {
                    value: Currency::new(0),
                    address: Address::new([0; 32]),
                },
                missed_host_value: Currency::new(0),
                total_collateral: Currency::new(0),
                host_public_key: PublicKey::new([0; 32]),
                renter_public_key: PublicKey::new([0; 32]),
                revision_number: 0,

                host_signature: Signature::new([0; 64]),
                renter_signature: Signature::new([0; 64]),
            },
            final_revision: FileContract {
                capacity: 0,
                filesize: 0,
                file_merkle_root: Hash256::default(),
                proof_height: 0,
                expiration_height: 0,
                renter_output: SiacoinOutput {
                    value: Currency::new(0),
                    address: Address::new([0; 32]),
                },
                host_output: SiacoinOutput {
                    value: Currency::new(0),
                    address: Address::new([0; 32]),
                },
                missed_host_value: Currency::new(0),
                total_collateral: Currency::new(0),
                host_public_key: PublicKey::new([0; 32]),
                renter_public_key: PublicKey::new([0; 32]),
                revision_number: 0,

                host_signature: Signature::new([0; 64]),
                renter_signature: Signature::new([0; 64]),
            },
            renter_rollover: Currency::new(0),
            host_rollover: Currency::new(0),
            renter_signature: Signature::new([0u8; 64]),
            host_signature: Signature::new([0u8; 64]),
        };

        let binary_str = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&fcr, binary_str);

        let json_str = "{\"finalRevision\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},\"newContract\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},\"renterRollover\":\"0\",\"hostRollover\":\"0\",\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}";
        test_serialize_json(&fcr, json_str);
    }

    #[test]
    fn test_serialize_storage_proof() {
        let sp = StorageProof {
            proof_index: ChainIndexElement {
                id: BlockID::default(),
                chain_index: ChainIndex {
                    id: BlockID::default(),
                    height: 0,
                },
                state_element: StateElement {
                    leaf_index: 0,
                    merkle_proof: vec![Hash256::default()],
                },
            },
            leaf: [3u8; 64].into(),
            proof: vec![Hash256::default()],
        };

        let binary_str = "0000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030301000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&sp, binary_str);

        let json_str = "{\"proofIndex\":{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"chainIndex\":{\"height\":0,\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}},\"leaf\":\"03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303\",\"proof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]}";
        test_serialize_json(&sp, json_str);
    }

    #[test]
    fn test_serialize_v2_file_contract_resolution() {
        struct TestCase {
            resolution: ContractResolution,
            binary_str: String,
            json_str: String,
        }
        let test_cases = vec![
			TestCase{
				resolution: ContractResolution::Renewal(FileContractRenewal {
						new_contract: FileContract {
							capacity: 0,
							filesize: 0,
							file_merkle_root: Hash256::default(),
							proof_height: 0,
							expiration_height: 0,
							renter_output: SiacoinOutput {
								value: Currency::new(0),
								address: Address::new([0; 32]),
							},
							host_output: SiacoinOutput {
								value: Currency::new(0),
								address: Address::new([0; 32]),
							},
							missed_host_value: Currency::new(0),
							total_collateral: Currency::new(0),
							host_public_key: PublicKey::new([0; 32]),
							renter_public_key: PublicKey::new([0; 32]),
							revision_number: 0,

							host_signature: Signature::new([0; 64]),
							renter_signature: Signature::new([0; 64]),
						},
						final_revision: FileContract {
							capacity: 0,
							filesize: 0,
							file_merkle_root: Hash256::default(),
							proof_height: 0,
							expiration_height: 0,
							renter_output: SiacoinOutput {
								value: Currency::new(0),
								address: Address::new([0; 32]),
							},
							host_output: SiacoinOutput {
								value: Currency::new(0),
								address: Address::new([0; 32]),
							},
							missed_host_value: Currency::new(0),
							total_collateral: Currency::new(0),
							host_public_key: PublicKey::new([0; 32]),
							renter_public_key: PublicKey::new([0; 32]),
							revision_number: 0,

							host_signature: Signature::new([0; 64]),
							renter_signature: Signature::new([0; 64]),
						},
						renter_rollover: Currency::new(0),
						host_rollover: Currency::new(0),
						renter_signature: Signature::new([0u8; 64]),
						host_signature: Signature::new([0u8; 64]),
					}),
				binary_str: "00000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
				json_str: "{\"parent\":{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"v2FileContract\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}},\"type\":\"renewal\",\"resolution\":{\"finalRevision\":{\"capacity\":0,\"expirationHeight\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"filesize\":0,\"hostOutput\":{\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"value\":\"0\"},\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"missedHostValue\":\"0\",\"proofHeight\":0,\"renterOutput\":{\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"value\":\"0\"},\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"totalCollateral\":\"0\"},\"hostRollover\":\"0\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"newContract\":{\"capacity\":0,\"expirationHeight\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"filesize\":0,\"hostOutput\":{\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"value\":\"0\"},\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"missedHostValue\":\"0\",\"proofHeight\":0,\"renterOutput\":{\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"value\":\"0\"},\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"totalCollateral\":\"0\"},\"renterRollover\":\"0\",\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}}".to_string(),
			},
			TestCase{
				resolution: ContractResolution::StorageProof(StorageProof{
							proof_index: ChainIndexElement {
								id: BlockID::default(),
								chain_index: ChainIndex {
									id: BlockID::default(),
									height: 0,
								},
								state_element: StateElement {
									leaf_index: 0,
									merkle_proof: vec![Hash256::default()],
								},
							},
							leaf: [0u8; 64].into(),
							proof: vec![Hash256::default()],
					}),
				binary_str: "00000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
				json_str: "{\"parent\":{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"v2FileContract\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}},\"type\":\"storageProof\",\"resolution\":{\"leaf\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"proof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"],\"proofIndex\":{\"chainIndex\":{\"height\":0,\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]}}}}".to_string(),
			},
			TestCase{
				resolution: ContractResolution::Finalization([0u8;64].into()),
				binary_str: "000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
				json_str: "{\"parent\":{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"v2FileContract\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}},\"type\":\"finalization\",\"resolution\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}".to_string(),
			},
			TestCase{
				resolution: ContractResolution::Expiration(),
				binary_str: "0000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003".to_string(),
				json_str: "{\"parent\":{\"stateElement\":{\"leafIndex\":0,\"merkleProof\":[\"0000000000000000000000000000000000000000000000000000000000000000\"]},\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"v2FileContract\":{\"capacity\":0,\"filesize\":0,\"fileMerkleRoot\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"hostSignature\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}},\"type\":\"expiration\",\"resolution\":{}}".to_string(),
			}
		];
        for tc in test_cases {
            let fcr = FileContractResolution {
                parent: FileContractElement {
                    id: FileContractID::default(),
                    state_element: StateElement {
                        leaf_index: 0,
                        merkle_proof: vec![Hash256::default()],
                    },
                    v2_file_contract: FileContract {
                        capacity: 0,
                        filesize: 0,
                        file_merkle_root: Hash256::default(),
                        proof_height: 0,
                        expiration_height: 0,
                        renter_output: SiacoinOutput {
                            value: Currency::new(0),
                            address: Address::new([0; 32]),
                        },
                        host_output: SiacoinOutput {
                            value: Currency::new(0),
                            address: Address::new([0; 32]),
                        },
                        missed_host_value: Currency::new(0),
                        total_collateral: Currency::new(0),
                        host_public_key: PublicKey::new([0; 32]),
                        renter_public_key: PublicKey::new([0; 32]),
                        revision_number: 0,

                        host_signature: Signature::new([0; 64]),
                        renter_signature: Signature::new([0; 64]),
                    },
                },
                resolution: tc.resolution,
            };

            test_serialize(&fcr, tc.binary_str.as_str());
            test_serialize_json(&fcr, tc.json_str.as_str());
        }
    }
}
