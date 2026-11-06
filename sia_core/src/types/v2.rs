use std::io;

use crate::consensus::ChainState;
use crate::encoding::{self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaDecode};
use blake2b_simd::Params;
use serde::de::{Error, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::io::AsyncRead;

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
    fn encoded_length(&self) -> usize {
        self.as_str().as_bytes().encoded_length()
    }

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

impl AsyncSiaDecodable for Protocol {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, encoding::Error> {
        let s = String::decode_async(r).await?;
        let v = Protocol::try_from(s).map_err(|e| encoding::Error::InvalidValue(e.to_string()))?;
        Ok(v)
    }
}

#[derive(Debug, PartialEq, Clone, SiaEncode, SiaDecode, AsyncSiaDecode, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode)]
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
        state.update(cs.v2_replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A FileContract is a storage agreement between a renter and a host. It
/// consists of a bidirectional payment channel that resolves as either "valid"
/// or "missed" depending on whether a valid StorageProof is submitted for the
/// contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode, Clone)]
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
    pub fn tax(&self, _cs: &ChainState) -> Currency {
        (self.renter_output.value + self.host_output.value) / Currency::new(25) // 4%
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
        state.update(cs.v2_replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A SiacoinElement is a record of a Siacoin UTXO within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinElement {
    pub state_element: StateElement,
    pub id: SiacoinOutputID,
    pub siacoin_output: SiacoinOutput,
    pub maturity_height: u64,
}

/// A SiafundElement is a record of a Siafund UTXO within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundElement {
    pub state_element: StateElement,
    pub id: SiafundOutputID,
    pub siafund_output: SiafundOutput,
    pub claim_start: Currency,
}

/// A V2FileContractElement is a record of a FileContract within the state
/// accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractElement {
    pub state_element: StateElement,
    pub id: FileContractID,
    pub v2_file_contract: FileContract,
}

/// A ChainIndexElement is a record of a ChainIndex within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode)]
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
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, AsyncSiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInput {
    pub parent: SiacoinElement,
    pub satisfied_policy: SatisfiedPolicy,
}

/// A V2SiafundInput represents a Siafund UTXO that is being spent in a v2
/// transaction.
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInput {
    pub parent: SiafundElement,
    pub claim_address: Address,
    pub satisfied_policy: SatisfiedPolicy,
}

/// A FileContractRevision updates the state of an existing file contract.
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, SiaEncode, SiaDecode)]
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
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractRenewal {
    pub final_renter_output: SiacoinOutput,
    pub final_host_output: SiacoinOutput,
    pub renter_rollover: Currency,
    pub host_rollover: Currency,
    pub new_contract: FileContract,

    // signatures cover above fields
    pub renter_signature: Signature,
    pub host_signature: Signature,
}

impl FileContractRenewal {
    fn encode_semantics<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.final_renter_output.encode(w)?;
        self.final_host_output.encode(w)?;
        self.renter_rollover.encode(w)?;
        self.host_rollover.encode(w)?;
        self.new_contract.encode_semantics(w)?;
        [0u8; 64].encode(w)?; // empty renter sig
        [0u8; 64].encode(w)?; // empty host sig
        Ok(())
    }

    pub fn sig_hash(&self, cs: &ChainState) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/sig/filecontractrenewal|".as_bytes());
        state.update(cs.v2_replay_prefix());
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A StorageProof asserts the presence of a randomly-selected leaf within the
/// Merkle tree of a V2FileContract's data.
#[derive(Debug, PartialEq, Serialize, Deserialize, AsyncSiaDecode, SiaEncode, SiaDecode)]
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
    fn encoded_length(&self) -> usize {
        1 + self.parent.encoded_length()
            + match &self.resolution {
                ContractResolution::Renewal(renewal) => renewal.encoded_length(),
                ContractResolution::StorageProof(proof) => proof.encoded_length(),
                ContractResolution::Expiration() => 0,
            }
    }
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

impl AsyncSiaDecodable for FileContractResolution {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, encoding::Error> {
        let parent = FileContractElement::decode_async(r).await?;
        let resolution_type = u8::decode_async(r).await?;
        let resolution = match resolution_type {
            0 => ContractResolution::Renewal(FileContractRenewal::decode_async(r).await?),
            1 => ContractResolution::StorageProof(StorageProof::decode_async(r).await?),
            2 => ContractResolution::Expiration(),
            _ => {
                return Err(encoding::Error::InvalidValue(format!(
                    "invalid contract resolution type: {resolution_type}"
                )));
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
    /// Writes the semantic encoding of the transaction.
    ///
    /// This should only be used for computing IDs and signature hashes. Use
    /// [`SiaEncodable::encode`] for full transaction serialization.
    pub fn encode_semantics<W: io::Write>(&self, w: &mut W) -> encoding::Result<()> {
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
        state.update(b"sia/id/transaction|");
        self.encode_semantics(&mut state).unwrap();
        state.finalize().into()
    }

    pub fn input_sig_hash(&self, cs: &ChainState) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state.update("sia/sig/input|".as_bytes());
        state.update(cs.v2_replay_prefix());
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
    fn encoded_length(&self) -> usize {
        let mut len = 9; // version + fields bitfield

        fn do_encode<T: SiaEncodable>(len: &mut usize, v: &[T]) {
            if !v.is_empty() {
                *len += v.encoded_length();
            }
        }

        do_encode(&mut len, &self.siacoin_inputs);
        do_encode(&mut len, &self.siacoin_outputs);
        do_encode(&mut len, &self.siafund_inputs);
        do_encode(&mut len, &self.siafund_outputs);
        do_encode(&mut len, &self.file_contracts);
        do_encode(&mut len, &self.file_contract_revisions);
        do_encode(&mut len, &self.file_contract_resolutions);
        do_encode(&mut len, &self.attestations);
        do_encode(&mut len, &self.arbitrary_data);
        if let Some(addr) = &self.new_foundation_address {
            len += addr.encoded_length();
        }
        if self.miner_fee != Currency::zero() {
            len += self.miner_fee.encoded_length();
        }

        len
    }
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

        fn do_encode<W: io::Write, T: SiaEncodable>(w: &mut W, v: &[T]) -> encoding::Result<()> {
            if !v.is_empty() { v.encode(w) } else { Ok(()) }
        }

        do_encode(w, &self.siacoin_inputs)?;
        do_encode(w, &self.siacoin_outputs)?;
        do_encode(w, &self.siafund_inputs)?;
        do_encode(w, &self.siafund_outputs)?;
        do_encode(w, &self.file_contracts)?;
        do_encode(w, &self.file_contract_revisions)?;
        do_encode(w, &self.file_contract_resolutions)?;
        do_encode(w, &self.attestations)?;
        do_encode(w, &self.arbitrary_data)?;
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

        fn do_decode<R: io::Read, T: SiaDecodable>(
            r: &mut R,
            condition: bool,
            default: fn() -> T,
        ) -> encoding::Result<T> {
            if condition {
                T::decode(r)
            } else {
                Ok(default())
            }
        }

        let fields = u64::decode(r)?;
        Ok(Transaction {
            siacoin_inputs: do_decode(r, fields & 1 != 0, Vec::new)?,
            siacoin_outputs: do_decode(r, fields & 2 != 0, Vec::new)?,
            siafund_inputs: do_decode(r, fields & 4 != 0, Vec::new)?,
            siafund_outputs: do_decode(r, fields & 8 != 0, Vec::new)?,
            file_contracts: do_decode(r, fields & 16 != 0, Vec::new)?,
            file_contract_revisions: do_decode(r, fields & 32 != 0, Vec::new)?,

            file_contract_resolutions: do_decode(r, fields & 64 != 0, Vec::new)?,
            attestations: do_decode(r, fields & 128 != 0, Vec::new)?,
            arbitrary_data: do_decode(r, fields & 256 != 0, Vec::new)?,
            new_foundation_address: if fields & 512 != 0 {
                Some(Address::decode(r)?)
            } else {
                None
            },
            miner_fee: do_decode(r, fields & 1024 != 0, Currency::zero)?,
        })
    }
}

impl AsyncSiaDecodable for Transaction {
    async fn decode_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, encoding::Error> {
        let version = u8::decode_async(r).await?;
        if version != TXN_VERSION {
            return Err(encoding::Error::InvalidValue(format!(
                "invalid transaction version: {version}"
            )));
        }

        async fn do_decode<R: AsyncRead + Unpin, T: AsyncSiaDecodable>(
            r: &mut R,
            condition: bool,
            default: fn() -> T,
        ) -> encoding::Result<T> {
            if condition {
                T::decode_async(r).await
            } else {
                Ok(default())
            }
        }

        let fields = u64::decode_async(r).await?;
        Ok(Transaction {
            siacoin_inputs: do_decode(r, fields & 1 != 0, Vec::new).await?,
            siacoin_outputs: do_decode(r, fields & 2 != 0, Vec::new).await?,
            siafund_inputs: do_decode(r, fields & 4 != 0, Vec::new).await?,
            siafund_outputs: do_decode(r, fields & 8 != 0, Vec::new).await?,
            file_contracts: do_decode(r, fields & 16 != 0, Vec::new).await?,
            file_contract_revisions: do_decode(r, fields & 32 != 0, Vec::new).await?,
            file_contract_resolutions: do_decode(r, fields & 64 != 0, Vec::new).await?,
            attestations: do_decode(r, fields & 128 != 0, Vec::new).await?,
            arbitrary_data: do_decode(r, fields & 256 != 0, Vec::new).await?,
            new_foundation_address: if fields & 512 != 0 {
                Some(Address::decode_async(r).await?)
            } else {
                None
            },
            miner_fee: do_decode(r, fields & 1024 != 0, Currency::zero).await?,
        })
    }
}

#[cfg(test)]
mod golden;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ElementAccumulator, HardforkASIC, HardforkDevAddr, HardforkFoundation, HardforkOak,
        HardforkStorageProof, HardforkTax, HardforkV2, Network, State,
    };
    use crate::types::Work;
    use chrono::{DateTime, Duration};

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
                    nonce_factor: 1009,
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
                    final_cut_height: 0,
                    ephemeral_output_height: 0,
                },
            },
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
                tax: Currency::new(13611294676837538538534984297270728458),
            },
            TestCase {
                output_value: Currency::new(805949712500000000000000000000000),
                tax: Currency::new(64475977000000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(151318823166141058930638084278357033939),
                tax: Currency::new(12105505853291284714451046742268562715),
            },
            TestCase {
                output_value: Currency::new(2087287149000000000000000000000000),
                tax: Currency::new(166982971920000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(19054329256128693174495496952954959442),
                tax: Currency::new(1524346340490295453959639756236396755),
            },
            TestCase {
                output_value: Currency::new(1463835551500000000000000000000000),
                tax: Currency::new(117106844120000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(34808017277671855105213753517013880976),
                tax: Currency::new(2784641382213748408417100281361110478),
            },
            TestCase {
                output_value: Currency::new(1456475819000000000000000000000000),
                tax: Currency::new(116518065520000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(4050009160038948139568737574567615426),
                tax: Currency::new(324000732803115851165499005965409234),
            },
            TestCase {
                output_value: Currency::new(611362349000000000000000000000000),
                tax: Currency::new(48908987920000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(59744399278834191323014460064531501644),
                tax: Currency::new(4779551942306735305841156805162520131),
            },
            TestCase {
                output_value: Currency::new(1971395366500000000000000000000000),
                tax: Currency::new(157711629320000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(129395477943018813820173885271365401215),
                tax: Currency::new(10351638235441505105613910821709232097),
            },
            TestCase {
                output_value: Currency::new(1562430843000000000000000000000000),
                tax: Currency::new(124994467440000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(33394010960011557818205782768368594560),
                tax: Currency::new(2671520876800924625456462621469487564),
            },
            TestCase {
                output_value: Currency::new(1464305596000000000000000000000000),
                tax: Currency::new(117144447680000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(33699424149038914903292787212706936885),
                tax: Currency::new(2695953931923113192263422977016554950),
            },
            TestCase {
                output_value: Currency::new(455795805000000000000000000000000),
                tax: Currency::new(36463664400000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(88567642754201788868008131876936390234),
                tax: Currency::new(7085411420336143109440650550154911218),
            },
            TestCase {
                output_value: Currency::new(359253930000000000000000000000000),
                tax: Currency::new(28740314400000000000000000000000),
            },
            TestCase {
                output_value: Currency::new(56501907684312465044405566127405468273),
                tax: Currency::new(4520152614744997203552445290192437461),
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
}
