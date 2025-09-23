use std::io;

use crate::consensus::ChainState;
use crate::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::encoding_async::{
    AsyncDecoder, AsyncEncoder, AsyncSiaDecodable, AsyncSiaDecode, AsyncSiaEncodable,
    AsyncSiaEncode,
};
use blake2b_simd::Params;
use serde::de::{Error, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::signing::{PublicKey, Signature};
use crate::types::common::BlockID;

use super::{
    Address, AttestationID, ChainIndex, Currency, FileContractID, Hash256, Leaf, SiacoinOutput,
    SiacoinOutputID, SiafundOutput, SiafundOutputID, StateElement, TransactionID,
};

// expose spend policies
pub use super::spendpolicy::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Protocol {
    SiaMux,
    QUIC,
}

#[derive(Debug, Error)]
pub enum ProtocolParseError {
    #[error("invalid protocol {0}")]
    InvalidProtocol(String),
}

impl Protocol {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Protocol::SiaMux => "siamux",
            Protocol::QUIC => "quic",
        }
    }
}

impl TryFrom<String> for Protocol {
    type Error = ProtocolParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "siamux" => Ok(Protocol::SiaMux),
            "quic" => Ok(Protocol::QUIC),
            _ => Err(ProtocolParseError::InvalidProtocol(value)),
        }
    }
}

impl Serialize for Protocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Protocol::try_from(s).map_err(|e| D::Error::custom(format!("{e:?}")))
    }
}

impl SiaEncodable for Protocol {
    fn encode<W: io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.as_str().as_bytes().encode(w)
    }
}

impl SiaDecodable for Protocol {
    fn decode<R: io::Read>(r: &mut R) -> encoding::Result<Self> {
        let s = String::decode(r)?;
        let v = Protocol::try_from(s).map_err(|e| encoding::Error::InvalidValue(e.to_string()))?;
        Ok(v)
    }
}

impl AsyncSiaEncodable for Protocol {
    async fn encode_async<E: AsyncEncoder>(&self, e: &mut E) -> Result<(), E::Error> {
        self.as_str().as_bytes().encode_async(e).await
    }
}

impl AsyncSiaDecodable for Protocol {
    async fn decode_async<D: AsyncDecoder>(d: &mut D) -> Result<Self, D::Error> {
        let s = String::decode_async(d).await?;
        let v = Protocol::try_from(s).map_err(|e| encoding::Error::InvalidValue(e.to_string()))?;
        Ok(v)
    }
}

#[derive(
    Debug,
    PartialEq,
    Clone,
    SiaEncode,
    SiaDecode,
    AsyncSiaEncode,
    AsyncSiaDecode,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct NetAddress {
    pub protocol: Protocol,
    pub address: String,
}

/// An Attestation associates a key-value pair with an identity. For example,
/// hosts attest to their network address by setting Key to "HostAnnouncement"
/// and Value to their address, thereby allowing renters to discover them.
/// Generally, an attestation for a particular key is considered to overwrite any
/// previous attestations with the same key. (This allows hosts to announce a new
/// network address, for example.)
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaEncode, AsyncSiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub public_key: PublicKey,
    pub key: String,
    #[serde(with = "crate::types::utils::base64")]
    pub value: Vec<u8>,

    pub signature: Signature,
}

impl Attestation {
    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.public_key.encode(w)?;
        self.key.encode(w)?;
        self.value.encode(w)?;
        [0u8; 64].encode(w) // empty sig
    }

    pub fn sig_hash(&self, cs: &ChainState) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/sig/attestation|".as_bytes());
        state.update(cs.replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A FileContract is a storage agreement between a renter and a host. It
/// consists of a bidirectional payment channel that resolves as either "valid"
/// or "missed" depending on whether a valid StorageProof is submitted for the
/// contract.
#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    SiaEncode,
    SiaDecode,
    AsyncSiaEncode,
    AsyncSiaDecode,
    Clone,
)]
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

impl FileContract {
    pub fn tax(&self, cs: &ChainState) -> Currency {
        let tax = (self.renter_output.value + self.host_output.value) / Currency::new(25); // 4%
        tax - (tax % Currency::new(cs.siafund_count() as u128))
    }

    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.capacity.encode(w)?;
        self.filesize.encode(w)?;
        self.file_merkle_root.encode(w)?;
        self.proof_height.encode(w)?;
        self.expiration_height.encode(w)?;
        self.renter_output.encode(w)?;
        self.host_output.encode(w)?;
        self.missed_host_value.encode(w)?;
        self.total_collateral.encode(w)?;
        self.renter_public_key.encode(w)?;
        self.host_public_key.encode(w)?;
        self.revision_number.encode(w)?;
        [0u8; 64].encode(w)?; // nil renter signature
        [0u8; 64].encode(w)?; // nil host signature
        Ok(())
    }

    pub fn sig_hash(&self, cs: &ChainState) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/sig/filecontract|".as_bytes());
        state.update(cs.replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A SiacoinElement is a record of a Siacoin UTXO within the state accumulator.
#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    SiaEncode,
    SiaDecode,
    AsyncSiaDecode,
    AsyncSiaEncode,
    Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinElement {
    pub state_element: StateElement,
    pub id: SiacoinOutputID,
    pub siacoin_output: SiacoinOutput,
    pub maturity_height: u64,
}

/// A SiafundElement is a record of a Siafund UTXO within the state accumulator.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode, AsyncSiaEncode,
)]
#[serde(rename_all = "camelCase")]
pub struct SiafundElement {
    pub state_element: StateElement,
    pub id: SiafundOutputID,
    pub siafund_output: SiafundOutput,
    pub claim_start: Currency,
}

/// A V2FileContractElement is a record of a FileContract within the state
/// accumulator.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode, AsyncSiaEncode,
)]
#[serde(rename_all = "camelCase")]
pub struct FileContractElement {
    pub state_element: StateElement,
    pub id: FileContractID,
    pub v2_file_contract: FileContract,
}

/// A ChainIndexElement is a record of a ChainIndex within the state accumulator.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode, AsyncSiaEncode,
)]
#[serde(rename_all = "camelCase")]
pub struct ChainIndexElement {
    pub state_element: StateElement,
    pub id: BlockID,
    pub chain_index: ChainIndex,
}

impl ChainIndexElement {
    pub fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.state_element.leaf_index.encode(w)?;
        Vec::<Hash256>::new().encode(w)?; // empty merkle proof
        self.id.encode(w)?;
        self.chain_index.encode(w)?;
        Ok(())
    }
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
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaEncode, AsyncSiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInput {
    pub parent: SiacoinElement,
    pub satisfied_policy: SatisfiedPolicy,
}

/// A V2SiafundInput represents a Siafund UTXO that is being spent in a v2
/// transaction.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, AsyncSiaEncode, SiaEncode, SiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInput {
    pub parent: SiafundElement,
    pub claim_address: Address,
    pub satisfied_policy: SatisfiedPolicy,
}

/// A FileContractRevision updates the state of an existing file contract.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, AsyncSiaEncode, SiaEncode, SiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct FileContractRevision {
    pub parent: FileContractElement,
    pub revision: FileContract,
}

impl FileContractRevision {
    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent.id.encode(w)?;
        self.revision.encode_semantics(w)?;
        Ok(())
    }
}

/// A FileContractRenewal renews a file contract with optional rollover
/// of any unspent funds.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, AsyncSiaEncode, SiaEncode, SiaDecode,
)]
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

impl FileContractRenewal {
    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.final_revision.encode_semantics(w)?;
        self.new_contract.encode_semantics(w)?;
        self.renter_rollover.encode(w)?;
        self.host_rollover.encode(w)?;
        [0u8; 64].encode(w)?; // empty renter sig
        [0u8; 64].encode(w)?; // empty host sig
        Ok(())
    }

    pub fn sig_hash(&self, cs: &ChainState) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/sig/filecontractrenewal|".as_bytes());
        state.update(cs.replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A StorageProof asserts the presence of a randomly-selected leaf within the
/// Merkle tree of a V2FileContract's data.
#[derive(
    Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, AsyncSiaEncode, SiaEncode, SiaDecode,
)]
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

impl StorageProof {
    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.proof_index.encode_semantics(w)?;
        self.leaf.encode(w)?;
        self.proof.encode(w)?;
        Ok(())
    }
}

// A ContractResolution closes a v2 file contract's payment channel. There
/// are four ways a contract can be resolved:
///
/// 1. The renter can finalize the contract's current state, preventing further
///    revisions and immediately creating its outputs.
///
/// 2. The renter and host can jointly renew the contract. The old contract is
///    finalized, and a portion of its funds are "rolled over" into a new contract.
///
/// 3. The host can submit a storage proof, asserting that it has faithfully
///    stored the contract data for the agreed-upon duration. A storage proof can only be submitted after the
///    contract's ProofHeight; this allows the renter (or host) to broadcast the
///    latest contract revision prior to the proof.
///
/// 4. Lastly, anyone can submit a contract expiration. Typically, an expiration
///    is only required if the host is unable or unwilling to sign a finalization or
///    renewal. An expiration can only be submitted after the contract's
///    ExpirationHeight; this gives the host a reasonable window of time after the
///    ProofHeight in which to submit a storage proof.
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

impl FileContractResolution {
    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent.id.encode(w)?;
        match &self.resolution {
            // type is not encoded in the resolution semantics
            ContractResolution::Renewal(renewal) => renewal.encode_semantics(w),
            ContractResolution::StorageProof(proof) => proof.encode_semantics(w),
            ContractResolution::Expiration() => Ok(()),
        }
    }
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
            ContractResolution::Expiration() => 2u8.encode(w),
        }
    }
}

impl SiaDecodable for FileContractResolution {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let parent = FileContractElement::decode(r)?;
        let resolution = match u8::decode(r)? {
            0 => ContractResolution::Renewal(FileContractRenewal::decode(r)?),
            1 => ContractResolution::StorageProof(StorageProof::decode(r)?),
            2 => ContractResolution::Expiration(),
            _ => {
                return Err(encoding::Error::Custom(
                    "invalid contract resolution type".to_string(),
                ));
            }
        };
        Ok(FileContractResolution { parent, resolution })
    }
}

impl AsyncSiaEncodable for FileContractResolution {
    async fn encode_async<E: AsyncEncoder>(&self, e: &mut E) -> Result<(), E::Error> {
        self.parent.encode_async(e).await?;
        match &self.resolution {
            ContractResolution::Renewal(renewal) => {
                0u8.encode_async(e).await?;
                renewal.encode_async(e).await
            }
            ContractResolution::StorageProof(proof) => {
                1u8.encode_async(e).await?;
                proof.encode_async(e).await
            }
            ContractResolution::Expiration() => 2u8.encode_async(e).await,
        }
    }
}

impl AsyncSiaDecodable for FileContractResolution {
    async fn decode_async<D: AsyncDecoder>(d: &mut D) -> Result<Self, D::Error> {
        let parent = FileContractElement::decode_async(d).await?;
        let resolution_type = u8::decode_async(d).await?;
        let resolution = match resolution_type {
            0 => ContractResolution::Renewal(FileContractRenewal::decode_async(d).await?),
            1 => ContractResolution::StorageProof(StorageProof::decode_async(d).await?),
            2 => ContractResolution::Expiration(),
            _ => {
                return Err(encoding::Error::InvalidValue(format!(
                    "invalid contract resolution type: {resolution_type}"
                ))
                .into());
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
                ContractResolution::Expiration() => "expiration",
            },
        )?;
        let resolution = match &self.resolution {
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
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siacoin_inputs: Vec<SiacoinInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siacoin_outputs: Vec<SiacoinOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siafund_inputs: Vec<SiafundInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siafund_outputs: Vec<SiafundOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contracts: Vec<FileContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contract_revisions: Vec<FileContractRevision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contract_resolutions: Vec<FileContractResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<Attestation>,
    #[serde(
        default,
        with = "crate::types::utils::base64",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub arbitrary_data: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_foundation_address: Option<Address>,
    pub miner_fee: Currency,
}

impl Transaction {
    fn encode_semantics<W: io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.siacoin_inputs.len().encode(w)?;
        for input in &self.siacoin_inputs {
            input.parent.id.encode(w)?;
        }
        self.siacoin_outputs.encode(w)?;
        self.siafund_inputs.len().encode(w)?;
        for input in &self.siafund_inputs {
            input.parent.id.encode(w)?;
        }
        self.siafund_outputs.encode(w)?;
        self.file_contracts.len().encode(w)?;
        for fc in &self.file_contracts {
            fc.encode_semantics(w)?;
        }
        self.file_contract_revisions.len().encode(w)?;
        for fcr in &self.file_contract_revisions {
            fcr.encode_semantics(w)?;
        }
        self.file_contract_resolutions.len().encode(w)?;
        for fcr in &self.file_contract_resolutions {
            fcr.encode_semantics(w)?;
        }
        self.attestations.encode(w)?;
        self.arbitrary_data.encode(w)?;
        self.new_foundation_address.encode(w)?;
        self.miner_fee.encode(w)?;
        Ok(())
    }

    pub fn id(&self) -> TransactionID {
        let mut state = Params::new().hash_length(32).to_state();
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }

    pub fn input_sig_hash(&self, cs: &ChainState) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/sig/input|".as_bytes());
        state.update(cs.replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction {
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            file_contracts: Vec::new(),
            file_contract_revisions: Vec::new(),
            file_contract_resolutions: Vec::new(),
            attestations: Vec::new(),
            arbitrary_data: Vec::new(),
            new_foundation_address: None,
            miner_fee: Currency::zero(),
        }
    }
}

const TXN_VERSION: u8 = 2;

impl SiaEncodable for Transaction {
    fn encode<W: io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        TXN_VERSION.encode(w)?;

        let fields = [
            !self.siacoin_inputs.is_empty(),
            !self.siacoin_outputs.is_empty(),
            !self.siafund_inputs.is_empty(),
            !self.siafund_outputs.is_empty(),
            !self.file_contracts.is_empty(),
            !self.file_contract_revisions.is_empty(),
            !self.file_contract_resolutions.is_empty(),
            !self.attestations.is_empty(),
            !self.arbitrary_data.is_empty(),
            self.new_foundation_address.is_some(),
            self.miner_fee != Currency::zero(),
        ]
        .iter()
        .enumerate()
        .filter(|&(_, condition)| *condition)
        .map(|(i, _)| 1 << i)
        .sum::<u64>();
        fields.encode(w)?;

        if !self.siacoin_inputs.is_empty() {
            self.siacoin_inputs.encode(w)?;
        }
        if !self.siacoin_outputs.is_empty() {
            self.siacoin_outputs.encode(w)?;
        }
        if !self.siafund_inputs.is_empty() {
            self.siafund_inputs.encode(w)?;
        }
        if !self.siafund_outputs.is_empty() {
            self.siafund_outputs.encode(w)?;
        }
        if !self.file_contracts.is_empty() {
            self.file_contracts.encode(w)?;
        }
        if !self.file_contract_revisions.is_empty() {
            self.file_contract_revisions.encode(w)?;
        }
        if !self.file_contract_resolutions.is_empty() {
            self.file_contract_resolutions.encode(w)?;
        }
        if !self.attestations.is_empty() {
            self.attestations.encode(w)?;
        }
        if !self.arbitrary_data.is_empty() {
            self.arbitrary_data.encode(w)?;
        }
        if let Some(addr) = &self.new_foundation_address {
            addr.encode(w)?;
        }
        if self.miner_fee != Currency::zero() {
            self.miner_fee.encode(w)?;
        }
        Ok(())
    }
}

impl SiaDecodable for Transaction {
    fn decode<R: io::Read>(r: &mut R) -> encoding::Result<Self> {
        let version = u8::decode(r)?;
        if version != TXN_VERSION {
            return Err(encoding::Error::Custom(
                "unsupported transaction version".to_string(),
            ));
        }

        let fields = u64::decode(r)?;
        let mut txn = Transaction {
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            file_contracts: Vec::new(),
            file_contract_revisions: Vec::new(),
            file_contract_resolutions: Vec::new(),
            attestations: Vec::new(),
            arbitrary_data: Vec::new(),
            new_foundation_address: None,
            miner_fee: Currency::zero(),
        };
        if fields & 1 != 0 {
            txn.siacoin_inputs = Vec::decode(r)?;
        }
        if fields & 2 != 0 {
            txn.siacoin_outputs = Vec::decode(r)?;
        }
        if fields & 4 != 0 {
            txn.siafund_inputs = Vec::decode(r)?;
        }
        if fields & 8 != 0 {
            txn.siafund_outputs = Vec::decode(r)?;
        }
        if fields & 16 != 0 {
            txn.file_contracts = Vec::decode(r)?;
        }
        if fields & 32 != 0 {
            txn.file_contract_revisions = Vec::decode(r)?;
        }
        if fields & 64 != 0 {
            txn.file_contract_resolutions = Vec::decode(r)?;
        }
        if fields & 128 != 0 {
            txn.attestations = Vec::decode(r)?;
        }
        if fields & 256 != 0 {
            txn.arbitrary_data = Vec::decode(r)?;
        }
        if fields & 512 != 0 {
            txn.new_foundation_address = Some(Address::decode(r)?);
        }
        if fields & 1024 != 0 {
            txn.miner_fee = Currency::decode(r)?;
        }

        Ok(txn)
    }
}

impl AsyncSiaEncodable for Transaction {
    async fn encode_async<E: AsyncEncoder>(&self, e: &mut E) -> Result<(), E::Error> {
        TXN_VERSION.encode_async(e).await?;

        let fields = [
            !self.siacoin_inputs.is_empty(),
            !self.siacoin_outputs.is_empty(),
            !self.siafund_inputs.is_empty(),
            !self.siafund_outputs.is_empty(),
            !self.file_contracts.is_empty(),
            !self.file_contract_revisions.is_empty(),
            !self.file_contract_resolutions.is_empty(),
            !self.attestations.is_empty(),
            !self.arbitrary_data.is_empty(),
            self.new_foundation_address.is_some(),
            self.miner_fee != Currency::zero(),
        ]
        .iter()
        .enumerate()
        .filter(|&(_, condition)| *condition)
        .map(|(i, _)| 1 << i)
        .sum::<u64>();
        fields.encode_async(e).await?;

        if !self.siacoin_inputs.is_empty() {
            self.siacoin_inputs.encode_async(e).await?;
        }
        if !self.siacoin_outputs.is_empty() {
            self.siacoin_outputs.encode_async(e).await?;
        }
        if !self.siafund_inputs.is_empty() {
            self.siafund_inputs.encode_async(e).await?;
        }
        if !self.siafund_outputs.is_empty() {
            self.siafund_outputs.encode_async(e).await?;
        }
        if !self.file_contracts.is_empty() {
            self.file_contracts.encode_async(e).await?;
        }
        if !self.file_contract_revisions.is_empty() {
            self.file_contract_revisions.encode_async(e).await?;
        }
        if !self.file_contract_resolutions.is_empty() {
            self.file_contract_resolutions.encode_async(e).await?;
        }
        if !self.attestations.is_empty() {
            self.attestations.encode_async(e).await?;
        }
        if !self.arbitrary_data.is_empty() {
            self.arbitrary_data.encode_async(e).await?;
        }
        if let Some(addr) = &self.new_foundation_address {
            addr.encode_async(e).await?;
        }
        if self.miner_fee != Currency::zero() {
            self.miner_fee.encode_async(e).await?;
        }
        Ok(())
    }
}

impl AsyncSiaDecodable for Transaction {
    async fn decode_async<D: AsyncDecoder>(d: &mut D) -> Result<Self, D::Error> {
        let version = u8::decode_async(d).await?;
        if version != TXN_VERSION {
            return Err(encoding::Error::InvalidValue(format!(
                "invalid transaction version: {version}"
            ))
            .into());
        }

        let fields = u64::decode_async(d).await?;
        let mut txn = Transaction {
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            file_contracts: Vec::new(),
            file_contract_revisions: Vec::new(),
            file_contract_resolutions: Vec::new(),
            attestations: Vec::new(),
            arbitrary_data: Vec::new(),
            new_foundation_address: None,
            miner_fee: Currency::zero(),
        };
        if fields & 1 != 0 {
            txn.siacoin_inputs = Vec::decode_async(d).await?;
        }
        if fields & 2 != 0 {
            txn.siacoin_outputs = Vec::decode_async(d).await?;
        }
        if fields & 4 != 0 {
            txn.siafund_inputs = Vec::decode_async(d).await?;
        }
        if fields & 8 != 0 {
            txn.siafund_outputs = Vec::decode_async(d).await?;
        }
        if fields & 16 != 0 {
            txn.file_contracts = Vec::decode_async(d).await?;
        }
        if fields & 32 != 0 {
            txn.file_contract_revisions = Vec::decode_async(d).await?;
        }
        if fields & 64 != 0 {
            txn.file_contract_resolutions = Vec::decode_async(d).await?;
        }
        if fields & 128 != 0 {
            txn.attestations = Vec::decode_async(d).await?;
        }
        if fields & 256 != 0 {
            txn.arbitrary_data = Vec::decode_async(d).await?;
        }
        if fields & 512 != 0 {
            txn.new_foundation_address = Some(Address::decode_async(d).await?);
        }
        if fields & 1024 != 0 {
            txn.miner_fee = Currency::decode_async(d).await?;
        }

        Ok(txn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ElementAccumulator, HardforkASIC, HardforkDevAddr, HardforkFoundation, HardforkOak,
        HardforkStorageProof, HardforkTax, HardforkV2, Network, State,
    };
    use crate::types::Work;
    use crate::{address, hash_256, public_key, siacoin_id};
    use chrono::{DateTime, Duration};
    use core::fmt::Debug;
    use serde::Serialize;
    use serde::de::DeserializeOwned;

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
                file_merkle_root: hash_256!(
                    "dc033023420634ed4c7685c82aa884eebe8415e16c57b6a55c673a5a98fa7b0d"
                ),
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

    fn test_chain_state() -> ChainState {
        ChainState {
            state: State {
                index: ChainIndex {
                    height: 1,
                    id: BlockID::default(),
                },
                prev_timestamps: [DateTime::UNIX_EPOCH; 11],
                depth: BlockID::default(),
                child_target: BlockID::default(),
                siafund_pool: Currency::new(0),
                oak_time: Duration::zero(),
                oak_target: BlockID::default(),
                foundation_primary_address: Address::new([0u8; 32]),
                foundation_failsafe_address: Address::new([0u8; 32]),
                total_work: Work::zero(),
                difficulty: Work::zero(),
                oak_work: Work::zero(),
                elements: ElementAccumulator::default(),
                attestations: 0,
            },
            network: Network {
                name: "test".to_string(),
                initial_coinbase: Currency::new(0),
                minimum_coinbase: Currency::new(0),
                initial_target: BlockID::default(),
                block_interval: Duration::seconds(1),
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
                    oak_time: Duration::zero(),
                    oak_target: BlockID::default(),
                },
                hardfork_oak: HardforkOak {
                    height: 0,
                    fix_height: 0,
                    genesis_timestamp: DateTime::UNIX_EPOCH,
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
        }
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
                resolution: ContractResolution::Expiration(),
                binary_str: "0000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002".to_string(),
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

    #[test]
    fn test_file_contract_tax() {
        struct TestCase {
            output_value: Currency,
            tax: Currency,
        }
        let test_cases = vec![
            TestCase {
                output_value: Currency::new(0),
                tax: Currency::new(0),
            },
            TestCase {
                output_value: Currency::new(0),
                tax: Currency::new(0),
            },
            TestCase {
                output_value: Currency::new(1),
                tax: Currency::new(0),
            },
            TestCase {
                output_value: Currency::new(170141183460469231731687303715884105727),
                tax: Currency::new(13611294676837538538534984297270720000),
            },
            TestCase {
                output_value: Currency::new(805949712500000000000000000000000),
                tax: Currency::new(64475977000000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(151318823166141058930638084278357033939),
                tax: Currency::new(12105505853291284714451046742268560000),
            },
            TestCase {
                output_value: Currency::new(2087287149000000000000000000000000),
                tax: Currency::new(166982971920000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(19054329256128693174495496952954959442),
                tax: Currency::new(1524346340490295453959639756236390000),
            },
            TestCase {
                output_value: Currency::new(1463835551500000000000000000000000),
                tax: Currency::new(117106844120000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(34808017277671855105213753517013880976),
                tax: Currency::new(2784641382213748408417100281361110000),
            },
            TestCase {
                output_value: Currency::new(1456475819000000000000000000000000),
                tax: Currency::new(116518065520000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(4050009160038948139568737574567615426),
                tax: Currency::new(324000732803115851165499005965400000),
            },
            TestCase {
                output_value: Currency::new(611362349000000000000000000000000),
                tax: Currency::new(48908987920000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(59744399278834191323014460064531501644),
                tax: Currency::new(4779551942306735305841156805162520000),
            },
            TestCase {
                output_value: Currency::new(1971395366500000000000000000000000),
                tax: Currency::new(157711629320000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(129395477943018813820173885271365401215),
                tax: Currency::new(10351638235441505105613910821709230000),
            },
            TestCase {
                output_value: Currency::new(1562430843000000000000000000000000),
                tax: Currency::new(124994467440000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(33394010960011557818205782768368594560),
                tax: Currency::new(2671520876800924625456462621469480000),
            },
            TestCase {
                output_value: Currency::new(1464305596000000000000000000000000),
                tax: Currency::new(117144447680000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(33699424149038914903292787212706936885),
                tax: Currency::new(2695953931923113192263422977016550000),
            },
            TestCase {
                output_value: Currency::new(455795805000000000000000000000000),
                tax: Currency::new(36463664400000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(88567642754201788868008131876936390234),
                tax: Currency::new(7085411420336143109440650550154910000),
            },
            TestCase {
                output_value: Currency::new(359253930000000000000000000000000),
                tax: Currency::new(28740314400000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(56501907684312465044405566127405468273),
                tax: Currency::new(4520152614744997203552445290192430000),
            },
        ];

        let cs = test_chain_state();
        for tc in test_cases.iter() {
            let fc = FileContract {
                capacity: 0,
                filesize: 0,
                file_merkle_root: Hash256::default(),
                revision_number: 0,
                proof_height: 0,
                expiration_height: 0,
                missed_host_value: Currency::new(0),
                total_collateral: Currency::new(0),
                host_public_key: PublicKey::new([0u8; 32]),
                renter_public_key: PublicKey::new([0u8; 32]),
                host_signature: Signature::new([0u8; 64]),
                renter_signature: Signature::new([0u8; 64]),
                renter_output: SiacoinOutput {
                    value: tc.output_value,
                    address: Address::default(),
                },
                host_output: SiacoinOutput {
                    value: tc.output_value,
                    address: Address::default(),
                },
            };

            let tax = fc.tax(&cs);
            assert_eq!(
                tax, tc.tax,
                "prefork tax incorrect for payout {:?}",
                tc.output_value
            );
        }
    }

    #[test]
    fn test_attestation_sig_hash() {
        let cs = test_chain_state();
        let a = Attestation {
            public_key: PublicKey::new([
                119, 70, 48, 66, 126, 125, 116, 9, 234, 170, 136, 51, 123, 122, 142, 138, 198, 136,
                19, 32, 194, 144, 129, 104, 130, 246, 58, 195, 16, 72, 139, 112,
            ]),
            key: "2d341885482102f2".to_string(),
            value: vec![113, 1, 70, 231, 190, 215, 117, 38],
            signature: Signature::default(),
        };
        let sig_hash = a.sig_hash(&cs);
        assert_eq!(
            hex::encode(sig_hash),
            "5c4201fd4c261a1a3deb25130bd8f06d7d87a46281fd022252152844336a7c17"
        )
    }

    #[test]
    fn test_file_contract_sig_hash() {
        let cs = test_chain_state();
        let s = "{\"capacity\":15437388468662742744,\"filesize\":16009828729725979578,\"fileMerkleRoot\":\"2d3b2c7b78f04eb1b66ac467ae7831081f7b495a2964b943c2c750e70180785a\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"2825068531000000000000000000000000\",\"address\":\"cf620149bcbde171fcd9611a32ba29e2e97687f3b1562c1fe14c504f642690c9d8f5ec3cbeaf\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"bee650e82a5534269bef42be0dd9a0b0f6c465b31437567075275d2188c685b2b65ef0fc7f369c780a758786f480da4d55459a1d85215f64aa47db1e79b1b8de\",\"hostSignature\":\"c32cf921ee00344d76e96e6f2dd306bd9c21226c83bb2ac55ce69b8d991a2f2212f645341c720f2fd8a7c57edef9b32f26a2c29c55958a45fd5c0d56a2addae3\"}";

        let fc: FileContract = serde_json::from_str(s).unwrap();
        let sig_hash = fc.sig_hash(&cs);
        assert_eq!(
            hex::encode(sig_hash),
            "0b9b74e471b8936e0045e752a1a22a77b7c17807ec98a1a3f272f6d917790325"
        );
    }

    #[test]
    fn test_contract_renewal_sig_hash() {
        let cs = test_chain_state();
        let s = "{\"finalRevision\":{\"capacity\":11959377077631068749,\"filesize\":10613077956865333006,\"fileMerkleRoot\":\"9482be576a5d68b6ad311b359b12070fae3df71fc0d2ec480a5ba8c3f4c9ad40\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"107325855000000000000000000000000\",\"address\":\"cc590b0901f908ee76ea2c8497b9c29d7f2250db4427b7b1dfd8d5c0a368845c4a70d66c8998\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"a71062c50866e8e834143340117efc49adbe7c8e50775c2ef6c2d8fd84470231928115e377288d588d93342946adbcbc83c5e3be01d4d22accf59c86f44ad523\",\"hostSignature\":\"a277c4b62d6ab7eead9d02c9e6243810baa0af9a8fef8b70b2f33df83fc8e67b94b2247b53c5e6d3a93a6197d41dd07652b75896757cf1dfeb059edca458de40\"},\"newContract\":{\"capacity\":2615073250361876210,\"filesize\":14611382285114970285,\"fileMerkleRoot\":\"5942d80cb6816da220a9576d62f3979b5e4f96b769cf785bcddf31698afb1432\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"4046664893000000000000000000000000\",\"address\":\"41b74682d50aed617224d17162150c3854cc290b522c20d62260466ef13a95e212b7d9c6778b\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"2614ae9d0b8300c98eadc1ffcab414298e30c678c0072359b1794623a04a68ef2474fbb1492071313b6f768946a52978b520c219a23649bfef9b9d0baabc7331\",\"hostSignature\":\"9c14a4f1428ad5bd72075c626fdf7dcf24143eda3a9cbecbc16ca751f0c88ee09e04a7f4f79718fb87df6debdd1d94d97bd00bcfa4fa77b3de582ad26eb45139\"},\"renterRollover\":\"3597839704000000000000000000000000\",\"hostRollover\":\"3099140907000000000000000000000000\",\"renterSignature\":\"4906067918dc6e7951c4e42b5b5bc1c3a3e3f02bddd10bf981275ccd0e8a5a067d35d4b5c2115256454490fed011e5c11ea35cb378eb6ada168b65d614515a44\",\"hostSignature\":\"5414a4c1e32f17b275148f3935a53b30cc30d1a0ff43e88f71e8308209282528a2942779638a6e2329314101e5ea79627d98b0f1b19830bf0ea89f670f7798bf\"}";

        let fcr: FileContractRenewal = serde_json::from_str(s).unwrap();
        let sig_hash = fcr.sig_hash(&cs);
        assert_eq!(
            hex::encode(sig_hash),
            "f20822926c53eac2bf91d54e5b39f7de76739226b131448e5508f077ebbccf3b"
        );
    }

    #[test]
    fn test_input_sig_hash() {
        let cs = test_chain_state();
        let s = "{\"siacoinInputs\":[{\"parent\":{\"id\":\"af88fb86ace93d500549ad5d3ccae9d75184c932d8b9f6b39b22dc1beb19cb2b\",\"stateElement\":{\"leafIndex\":17247661272366213787,\"merkleProof\":[\"419c0046c59819e4541a3810134dac5c975eb61cb12382c0fbad713257a9efd3\"]},\"siacoinOutput\":{\"value\":\"3088711336000000000000000000000000\",\"address\":\"c6b4adae9284845d1075bc33a68d281bf02ed406206f58a50d13191af7b6f617933bf733cd42\"},\"maturityHeight\":0},\"satisfiedPolicy\":{\"policy\":{\"type\":\"pk\",\"policy\":\"ed25519:e655ec65952c4953c904c9ee16961dfb02e8689f1f82fcfd9e387c8ea1104a2b\"},\"signatures\":[\"7ba834e5e33ca4ac7ad7dbd2b3bd42c7ae62db25263feb2a51777f5c8d5569b1eb28e349544689d3f96242a66d33dcdebeab4e5fa30c906fd2caaf83c16f3bfe\"]}}],\"siacoinOutputs\":[{\"value\":\"1597553234000000000000000000000000\",\"address\":\"bc99db1f50a653604797de23d535c9fbf73b493ab70089c7716c1e5c5fc2d0a578575d367eb0\"}],\"fileContracts\":[{\"capacity\":10874342648285931495,\"filesize\":13810078500867640614,\"fileMerkleRoot\":\"424b9304a9fccf94945ef14c6377060be59fb7d58ac8c952d67be05c67d863a2\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"1556050983000000000000000000000000\",\"address\":\"4505c61036d22e5075c676ea5906a645eb1cfa9a6a53d933ecfa198654b7d3f0fe74bdfbdaef\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"84d8091517ff09f11df171b21a1414200ea7074664c7e27d9de13c44bbb6cbc0de6de5783c6955065a77035bb2d92974fb5f11aa0dae9ac50dbddbb17d63d7fc\",\"hostSignature\":\"2fad832ddb5d6b11893851df4ecbd9a4b512a7a425dda67ac0da1604a0e8781d04e29cef928f31be706e6fc81089048ea87366449450e3da941a0b04487582f2\"}],\"fileContractRevisions\":[{\"parent\":{\"id\":\"22e9e60d81478b36fc44ee67b8d8ba874d196fc6e9c56bfacd5fcecdde39b736\",\"stateElement\":{\"leafIndex\":12023426945600912207,\"merkleProof\":[\"a0efcbdbe1f8e1b4fb6615eccac5948303d5a2c5afedda0baf658e5bbe41896e\"]},\"v2FileContract\":{\"capacity\":10776473623907646048,\"filesize\":7973631990249562263,\"fileMerkleRoot\":\"acd56f68224de7828076cb53f3476413819c8c78dde2461422c5a96644fba623\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"842083234000000000000000000000000\",\"address\":\"150084c56cd2bc38e80220eb69a485b5c298ee3c9f7fcc046c6b975ea8fb70f9098afe1ad85b\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"94dd2555507b81cfd927b36891a9b37465c00cb46a61d96ede5f760f1c5a5cadabb8c7719adb5cb088eec92d9a9c52497973fc2b5d0c54a2dfa04e35490e25b5\",\"hostSignature\":\"d66133988a412e5542535e9a6c3815396c46020a4ad693074d6681049b39c438af9dd395478566e193263e8acfa915848ec23ff47a95eca51bac4ede2a92f634\"}},\"revision\":{\"capacity\":6034084714889303577,\"filesize\":12020548219123782123,\"fileMerkleRoot\":\"2ce9c19107be51ab776221d61300c6c1aa32c2195246473eb15d7db12ec0943f\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"2247488091000000000000000000000000\",\"address\":\"6f7add99e7eba38429b101ff31190aa3a148c0087a3ad775790a8e01a90f71a94ca9ba2ffc71\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"7fb556fef4bfea24f7b9472b1b9874be600795da4535107d3910085a3e34c5818a60bd77d0bcbd92e6dbec604f1b67d827ba02072e83abfac217a2294157c53f\",\"hostSignature\":\"77664782e2c1dd42a3669f11f0519630561a4c0b48552c89bb74f79367f21fd73b6bc5ea112502f81bbc9e3df3b916158486c2e17145b95e5307ca56fb37fc6c\"}}],\"fileContractResolutions\":[{\"parent\":{\"id\":\"6b8527472e1143e07099e3f516f56ac2b46860f13652582b2abb6fffeac1f5d9\",\"stateElement\":{\"leafIndex\":14811616376775388856,\"merkleProof\":[\"bf4325ff8d463ba3bf62e9f697911a4bf8038971298440f4a2c5e010730ac594\"]},\"v2FileContract\":{\"capacity\":6642268570724229223,\"filesize\":15896577861535581162,\"fileMerkleRoot\":\"6e19255c03515dbbee1280f8e13e7378810243042a01a439849c0ddbc0fd7eac\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"2825432965000000000000000000000000\",\"address\":\"2ca7f5d7cbd79fbf4b5f2f5a4ead652342dd0413e39e9406b2935c53162d9347359d0477b320\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"169330702f83d499de6bff18cc7c2474785e02b8101baf8427407e9f6cc3ee6e7768b7e6ef929a6510c1b0ac1c24eab8090af84c27c772c80201fe93da535e17\",\"hostSignature\":\"29bf20483727c327e36c3085a87d91ad3072ca82f5d62da1d9895980320ab7a65d133bb147d55bd97c9f5a36a85afbfb8d9209ac82afaca18df64054394f0f08\"}},\"type\":\"expiration\",\"resolution\":{}},{\"parent\":{\"id\":\"2dd1bedefe81f2914ddf9f61c9d714d134d0af7a75d1c1322474d5e8eea342f2\",\"stateElement\":{\"leafIndex\":11863728860462350395,\"merkleProof\":[\"91a391d6104f76e439580a90f56fec3c07d01ad5535315416243ae6d8e17289d\"]},\"v2FileContract\":{\"capacity\":3158332065060007910,\"filesize\":11561455863259225844,\"fileMerkleRoot\":\"b4db7aa14dc851a348e0981c3ed1161dc286bca85424da42609b3c12f5f31ee6\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"2522086295000000000000000000000000\",\"address\":\"36e4ed130d7a9f0cbcdd0ed6fa78738dcd9eb6e779fc7501dd06f7cf968ce215e33778f0c79e\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"ff79f46439dd108ebe2c42434a11b916f7dee6f018798435b3c34a92ca121d3e21c0282d4efba4982a36e2cfe146e3c8ee31ba545911857a93d947faef543e2f\",\"hostSignature\":\"7f45f2f977e574ea980a0842f48d216b6680d129a98056cafa7f108487457bde8e0cd1cc5d74ba3187170f214115827bc961f0163203c479c3d4ab7e19f3d31f\"}},\"type\":\"storageProof\",\"resolution\":{\"proofIndex\":{\"id\":\"90da2d2ed68b716be7617b8c35c713ad66584a1dbf564cc44c09b6f3815e1d79\",\"stateElement\":{\"leafIndex\":1814794313179331469,\"merkleProof\":[\"8a3990c651140b9486c09559c54623a4e8ca5c2705a7de2b0b54de6d97e6d01d\"]},\"chainIndex\":{\"height\":17891680254001945312,\"id\":\"e5b6bf4a036b93d8a178ffe86ee209502a0ff3d45d2b3216052267b7a5561d21\"}},\"leaf\":\"c5e078423107b4d2c0ab10509404c525343e96eff45ea6353039194470aec04e3994d52cd2d9a6cbbd3709387207f59f063bec4e7266f6fa0c6dfcf7d7634a1c\",\"proof\":[\"f900e345a663fb6ec9eca5721a81e25fae111e50f38aeb76fd6258f2d4cecd86\"]}},{\"parent\":{\"id\":\"49d9f6a8cfae42cd9cc4d792b1799ab2752be164cd86ce5e474fe3731c31b492\",\"stateElement\":{\"leafIndex\":376572300431080610,\"merkleProof\":[\"b2945edc55afbc2344d201baaed373fc0a737c00216186c5e724c3e7d681a705\"]},\"v2FileContract\":{\"capacity\":14165001982102687892,\"filesize\":5514344128076756235,\"fileMerkleRoot\":\"3bcf704f911a925eea72629d71352e1f402fc7d3b632f0df6e203089a6fd9092\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"1548819653000000000000000000000000\",\"address\":\"c1f4c5d401041e4eb68455283ce6705f2dcdc5ac4d700f7dc233b13f91bbfa986aec255c62bb\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"ac99ce31b11341a8835e2666eed317b0042d45ce6ccb52a11a3d2d6c7ec050f432ea8e1fef95b3481da64c5b2b3a772459db094a68d4a3cf52f2e928f3dd7b55\",\"hostSignature\":\"c8a097593157a24390c5fc77bed87c54355e03572ff2b49137801c51ac55ff092141dfb46505808fa97ee22e839d682f9de7f595896338ebf1c4e1885067747c\"}},\"type\":\"renewal\",\"resolution\":{\"finalRevision\":{\"capacity\":6539007356562521256,\"filesize\":17290867016333557028,\"fileMerkleRoot\":\"ebaa3f96d6572cc3caf3036468ddf52ef6fbfcc3eacef4cffd6eabcd43d1b91a\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"2415984205000000000000000000000000\",\"address\":\"1300755d91ac9d739e168f5e54eb2aba9aa0c29cc29142ab4babf0e92be83f17cde6a5ff4ed5\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":18446744073709551615,\"renterSignature\":\"a1489731bddba377854020ae706127938ce95c617d22db29b9f9aa331ee27dbfb625b67b3418647b40d4ab4f0075a69a10d66840a3cec4b3c86112ce7e648761\",\"hostSignature\":\"4181fc7c46f09d0124c365a1aeba76f906d99afb3f49d6637f54fc4e2746776a8f3aa343bc823c705c11a581a87ddb918d9bccec0cb2deb46aa4627cf5cf3e80\"},\"newContract\":{\"capacity\":2724141139581307456,\"filesize\":2682841277844293416,\"fileMerkleRoot\":\"62ea0682d909fb36df6557ea2d8174b20db44c0ad1ed692b7b11b40893147e36\",\"proofHeight\":0,\"expirationHeight\":0,\"renterOutput\":{\"value\":\"4004958805000000000000000000000000\",\"address\":\"cc6a403530f6da43fb262723a9536a96666bd74075d64dd7d0eb65df5c494c24b115cdee00c5\"},\"hostOutput\":{\"value\":\"0\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"missedHostValue\":\"0\",\"totalCollateral\":\"0\",\"renterPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"hostPublicKey\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":0,\"renterSignature\":\"ed98b9027f795d3eeafac4928963a55189066fa8a447fd70041d498d6d1072ad5247d36cd657e1f5163889f14591e89159daca5c8c3e645af9b26ac782990cfc\",\"hostSignature\":\"841fff506bfbdc5c9f6dcda6de472dd6bc7e73e5f0974e0bc979fdcc24059246590ef2f6af2b75a786c27f78f43a27e5da91b320736a5cbb7bb15be8375e372e\"},\"renterRollover\":\"3037399761000000000000000000000000\",\"hostRollover\":\"2211277679000000000000000000000000\",\"renterSignature\":\"745f21dae4f1fba04c2d9b09ae69a9e5f096cf26707447fb3b1c17e486b71589b7dc5fda40ef08eac2122b51606b2fbe84211c5f6507631456ac0dd0ee164ef3\",\"hostSignature\":\"0510b572606c3144a4472538b722c2420165efda406b92b74457459d5c5b90a622490d7a70bd7e5e40b031fadd9d3edd90c13226869d8d358512aab5b0145a11\"}}],\"attestations\":[{\"publicKey\":\"ed25519:269ba257f490941f5fcfde5313e326fa205a1a8d91715d91f892581d7282bf21\",\"key\":\"629109f07df18f46\",\"value\":\"Adg+GFWhwVo=\",\"signature\":\"d44eb9a001803f52814adae65da4dc195d760e7afb00b9593716e54a116db7b98ad8e774e101098d31abca3b389a01a08438d7a33508f1f665d2d48f4524509d\"}],\"minerFee\":\"2208027072000000000000000000000000\"}";
        let txn: Transaction = serde_json::from_str(s).unwrap();
        let sig_hash = txn.input_sig_hash(&cs);
        assert_eq!(
            hex::encode(sig_hash),
            "aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422"
        );
    }

    #[test]
    fn test_transaction_serialization() {
        let txn = Transaction {
            siacoin_inputs: vec![],
            siacoin_outputs: vec![],
            siafund_inputs: vec![],
            siafund_outputs: vec![],
            file_contracts: vec![],
            file_contract_revisions: vec![],
            file_contract_resolutions: vec![],
            attestations: vec![],
            new_foundation_address: None,
            arbitrary_data: vec![],
            miner_fee: Currency::new(0),
        };
        test_serialize_json(&txn, "{\"minerFee\":\"0\"}");
        test_serialize(&txn, "020000000000000000");

        let txn = Transaction {
            siacoin_inputs: vec![SiacoinInput {
                parent: SiacoinElement{
                    id: siacoin_id!("aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422"),
                    state_element: StateElement{
                        leaf_index: 12312413,
                        merkle_proof: vec![hash_256!("aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422")]
                    },
                    siacoin_output: SiacoinOutput{
                        value: Currency::new(100),
                        address: address!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0")
                    },
                    maturity_height: 0,
                },
                satisfied_policy: SatisfiedPolicy {
                    policy: SpendPolicy::public_key(public_key!("ed25519:aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422")),
                    signatures: vec![
                        "aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422".parse().unwrap()
                    ],
                    preimages: vec![],
                },
            },
            ],
            siacoin_outputs: vec![SiacoinOutput {
                value: Currency::new(100),
                address: address!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0")
            }],
            siafund_inputs: vec![],
            siafund_outputs: vec![],
            file_contracts: vec![],
            file_contract_revisions: vec![],
            file_contract_resolutions: vec![],
            attestations: vec![],
            new_foundation_address: None,
            arbitrary_data: vec![],
            miner_fee: Currency::new(123581),
        };
        test_serialize(
            &txn,
            "02030400000000000001000000000000005ddfbb00000000000100000000000000aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422640000000000000000000000000000008fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c00000000000000000103aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f14220100000000000000aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f142200000000000000000100000000000000640000000000000000000000000000008fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cbde20100000000000000000000000000",
        );
        test_serialize_json(
            &txn,
            "{\"siacoinInputs\":[{\"parent\":{\"stateElement\":{\"leafIndex\":12312413,\"merkleProof\":[\"aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422\"]},\"id\":\"aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422\",\"siacoinOutput\":{\"value\":\"100\",\"address\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0\"},\"maturityHeight\":0},\"satisfiedPolicy\":{\"policy\":{\"type\":\"pk\",\"policy\":\"ed25519:aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422\"},\"signatures\":[\"aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422aefb1120a3f69fc8293caeb0bd36b4637d6fdf12f2f60494a2875358552f1422\"]}}],\"siacoinOutputs\":[{\"value\":\"100\",\"address\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0\"}],\"minerFee\":\"123581\"}",
        );
    }
}
