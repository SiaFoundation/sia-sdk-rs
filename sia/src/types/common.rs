use core::fmt;

use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::encoding::{
    self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode,
    V1SiaEncodable, V1SiaEncode,
};
use crate::macros::impl_hash_id;
use crate::types::currency::Currency;
use crate::types::v1;

use super::{specifier, Specifier};

impl_hash_id!(Hash256);
impl_hash_id!(SiacoinOutputID);
impl_hash_id!(AttestationID);

impl_hash_id!(SiafundOutputID);

impl SiafundOutputID {
    /// claim_output_id returns the SiacoinOutputID for the claim output of the siafund output
    pub fn claim_output_id(&self) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(self.as_ref());
        state.finalize().into()
    }

    pub fn v2_claim_output_id(&self) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(b"sia/id/v2siacoinclaimoutput|");
        state.update(self.as_ref());
        state.finalize().into()
    }
}

impl_hash_id!(BlockID);

impl BlockID {
    const FOUNDATION_OUTPUT_ID_PREFIX: Specifier = specifier!("foundation");

    pub fn foundation_output_id(&self) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(self.as_ref());
        state.update(Self::FOUNDATION_OUTPUT_ID_PREFIX.as_ref());
        state.finalize().into()
    }

    pub fn miner_output_id(&self, i: usize) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(self.as_ref());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }
}

impl_hash_id!(TransactionID);

impl TransactionID {
    const V2_SIACOIN_OUTPUT_PREFIX: &[u8] = b"sia/id/siacoinoutput|";
    const V2_SIAFUND_OUTPUT_PREFIX: &[u8] = b"sia/id/siafundoutput|";
    const V2_FILE_CONTRACT_PREFIX: &[u8] = b"sia/id/filecontract|";
    const V2_ATTESTATION_PREFIX: &[u8] = b"sia/id/attestation|";

    fn derive_v2_child_id<T: From<blake2b_simd::Hash>>(&self, prefix: &[u8], i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(prefix.as_ref());
        state.update(self.as_ref());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    /// v2_siacoin_output_id returns the SiacoinOutputID for the i-th siacoin output of the V2 transaction
    pub fn v2_siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
        self.derive_v2_child_id(Self::V2_SIACOIN_OUTPUT_PREFIX, i)
    }

    /// v2_siafund_output_id returns the SiafundOutputID for the i-th siafund output of the V2 transaction
    pub fn v2_siafund_output_id(&self, i: usize) -> SiafundOutputID {
        self.derive_v2_child_id(Self::V2_SIAFUND_OUTPUT_PREFIX, i)
    }

    /// v2_file_contract_id returns the FileContractID for the i-th file contract of the V2 transaction
    pub fn v2_file_contract_id(&self, i: usize) -> FileContractID {
        self.derive_v2_child_id(Self::V2_FILE_CONTRACT_PREFIX, i)
    }

    /// v2_attestation_id returns the AttestationID for the i-th attestation of the V2 transaction
    pub fn v2_attestation_id(&self, i: usize) -> AttestationID {
        self.derive_v2_child_id(Self::V2_ATTESTATION_PREFIX, i)
    }
}

impl_hash_id!(FileContractID);

impl FileContractID {
    const PROOF_OUTPUT_ID_PREFIX: Specifier = specifier!("storage proof");
    const V2_PROOF_OUTPUT_ID_PREFIX: &'static str = "id/v2filecontractoutput";
    const V2_FILE_CONTRACT_RENEWAL_PREFIX: &'static str = "id/v2filecontractrenewal";

    fn derive_proof_output_id<T: From<blake2b_simd::Hash>>(&self, valid: bool, i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(Self::PROOF_OUTPUT_ID_PREFIX.as_ref());
        state.update(self.as_ref());
        state.update(&(valid as u8).to_le_bytes());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    fn derive_v2_proof_output_id<T: From<blake2b_simd::Hash>>(&self, i: usize) -> T {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(Self::V2_PROOF_OUTPUT_ID_PREFIX.as_ref());
        state.update(self.as_ref());
        state.update(&(i as u64).to_le_bytes());
        state.finalize().into()
    }

    /// valid_output_id returns the SiacoinOutputID for the i-th valid output of the contract
    pub fn valid_output_id(&self, i: usize) -> SiacoinOutputID {
        self.derive_proof_output_id(true, i)
    }

    /// missed_output_id returns the SiacoinOutputID for the i-th missed output of the contract
    pub fn missed_output_id(&self, i: usize) -> SiacoinOutputID {
        self.derive_proof_output_id(false, i)
    }

    /// v2_renter_output_id returns the SiacoinOutputID for the renter output of a V2 file contract
    pub fn v2_renter_output_id(&self) -> SiacoinOutputID {
        self.derive_v2_proof_output_id(0)
    }

    /// v2_host_output_id returns the SiacoinOutputID for the host output of a V2 file contract
    pub fn v2_host_output_id(&self) -> SiacoinOutputID {
        self.derive_v2_proof_output_id(1)
    }

    /// v2_renewal_id returns the ID of the new contract created by renewing a V2 contract
    pub fn v2_renewal_id(&self) -> FileContractID {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(Self::V2_FILE_CONTRACT_RENEWAL_PREFIX.as_ref());
        state.update(self.as_ref());
        state.finalize().into()
    }
}

#[derive(Debug, PartialEq, SiaEncode, SiaDecode, Serialize, Deserialize)]
pub struct ChainIndex {
    pub height: u64,
    pub id: BlockID,
}

impl ChainIndex {
    pub fn child_height(&self) -> u64 {
        self.height + 1
    }
}

impl fmt::Display for ChainIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.height, hex::encode(self.id))
    }
}

/// A Block is a collection of transactions
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(rename = "parentID")]
    pub parent_id: BlockID,
    pub nonce: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub miner_payouts: Vec<SiacoinOutput>,
    pub transactions: Vec<v1::Transaction>,
}

impl V1SiaEncodable for Block {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent_id.encode(w)?;
        self.nonce.encode(w)?;
        self.timestamp.encode(w)?;
        self.miner_payouts.encode_v1(w)?;
        self.transactions.encode_v1(w)
    }
}

impl V1SiaDecodable for Block {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        Ok(Block {
            parent_id: BlockID::decode(r)?,
            nonce: u64::decode(r)?,
            timestamp: OffsetDateTime::decode(r)?,
            miner_payouts: Vec::<SiacoinOutput>::decode_v1(r)?,
            transactions: Vec::<v1::Transaction>::decode_v1(r)?,
        })
    }
}

/// encapsulates the various errors that can occur when parsing a Sia object
/// from a string
#[derive(Debug, PartialEq)]
pub enum HexParseError {
    MissingPrefix,
    InvalidLength,
    InvalidPrefix,
    InvalidChecksum, // not every object has a checksum
    HexError(hex::FromHexError),
}

/// An address that can be used to receive UTXOs
#[derive(Default, Debug, PartialEq, Clone, SiaEncode, V1SiaEncode, SiaDecode, V1SiaDecode)]
pub struct Address([u8; 32]);

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::parse_string(&s).map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl Address {
    pub const fn new(addr: [u8; 32]) -> Address {
        Address(addr)
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        if s.len() != 76 {
            return Err(HexParseError::InvalidLength);
        }

        let mut data = [0u8; 38];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&data[..32])
            .finalize();
        let checksum = h.as_bytes();

        if checksum[..6] != data[32..] {
            return Err(HexParseError::InvalidChecksum);
        }

        Ok(data[..32].into())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Address {
    fn from(val: &[u8]) -> Self {
        let mut data = [0u8; 32];
        data.copy_from_slice(val);
        Address(data)
    }
}

impl From<[u8; 32]> for Address {
    fn from(val: [u8; 32]) -> Self {
        Address(val)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 32 + 6];
        buf[..32].copy_from_slice(&self.0);

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&self.0)
            .finalize();

        buf[32..].copy_from_slice(&h.as_bytes()[..6]);
        write!(f, "{}", hex::encode(buf))
    }
}

/// A SiacoinOutput is a Siacoin UTXO that can be spent using the unlock conditions
/// for Address
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, V1SiaEncode, V1SiaDecode, Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

/// A SiafundOutput is a Siafund UTXO that can be spent using the unlock conditions
/// for Address
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundOutput {
    pub value: u64,
    pub address: Address,
}

impl V1SiaEncodable for SiafundOutput {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        Currency::new(self.value as u128).encode_v1(w)?;
        self.address.encode_v1(w)?;
        Currency::new(0).encode_v1(w) // siad encodes a "claim start," but its an error if it's non-zero.
    }
}

impl V1SiaDecodable for SiafundOutput {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let se = SiafundOutput {
            value: Currency::decode_v1(r)?
                .try_into()
                .map_err(|_| encoding::Error::Custom("invalid value".to_string()))?,
            address: Address::decode_v1(r)?,
        };
        Currency::decode_v1(r)?; // ignore claim start
        Ok(se)
    }
}

/// A Leaf is a 64-byte piece of data that is stored in a Merkle tree.
#[derive(Debug, PartialEq, Clone, SiaEncode, V1SiaEncode, SiaDecode, V1SiaDecode)]
pub struct Leaf([u8; 64]);

impl Leaf {
    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        if s.len() != 128 {
            return Err(HexParseError::InvalidLength);
        }

        let mut data = [0u8; 64];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;
        Ok(Leaf(data))
    }
}

impl From<[u8; 64]> for Leaf {
    fn from(data: [u8; 64]) -> Self {
        Leaf(data)
    }
}

impl fmt::Display for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Serialize for Leaf {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for Leaf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let data = hex::decode(s).map_err(|e| serde::de::Error::custom(format!("{e:?}")))?;
        if data.len() != 64 {
            return Err(serde::de::Error::custom("invalid length"));
        }
        Ok(Leaf(data.try_into().unwrap()))
    }
}

/// A StateElement is a generic element within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StateElement {
    pub leaf_index: u64,
    pub merkle_proof: Vec<Hash256>,
}

#[cfg(test)]
mod tests {
    use crate::{
        address, block_id, contract_id, public_key, siacoin_id, siafund_id, transaction_id,
    };

    use super::*;

    #[test]
    fn test_serialize_hash256() {
        let hash_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let hash = Hash256(hex::decode(hash_str).unwrap().try_into().unwrap());

        // binary
        let mut hash_serialized: Vec<u8> = Vec::new();
        hash.encode(&mut hash_serialized).unwrap();
        assert_eq!(hash_serialized, hex::decode(hash_str).unwrap());
        let hash_deserialized = Hash256::decode(&mut &hash_serialized[..]).unwrap();
        assert_eq!(hash_deserialized, hash); // deserialize

        // json
        let hash_serialized = serde_json::to_string(&hash).unwrap();
        let hash_deserialized: Hash256 = serde_json::from_str(&hash_serialized).unwrap();
        assert_eq!(hash_serialized, format!("\"{hash_str}\"")); // serialize
        assert_eq!(hash_deserialized, hash); // deserialize
    }

    #[test]
    fn test_serialize_address() {
        let addr_str = "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c";
        let checksum = "df32abee86f0";
        let address = address!(
            "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0"
        );

        // binary
        let mut addr_serialized: Vec<u8> = Vec::new();
        address.encode(&mut addr_serialized).unwrap();
        assert_eq!(addr_serialized, hex::decode(addr_str).unwrap()); // serialize
        let addr_deserialized = Address::decode(&mut &addr_serialized[..]).unwrap();
        assert_eq!(addr_deserialized, address); // deserialize

        // json
        let addr_serialized = serde_json::to_string(&address).unwrap();
        let addr_deserialized: Address = serde_json::from_str(&addr_serialized).unwrap();
        assert_eq!(addr_serialized, format!("\"{addr_str}{checksum}\"")); // serialize
        assert_eq!(addr_deserialized, address); // deserialize
    }

    #[test]
    fn test_serialize_block() {
        let b = Block{
            parent_id: block_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c"),
            nonce: 1236112,
            timestamp: OffsetDateTime::UNIX_EPOCH,
            miner_payouts: vec![
                SiacoinOutput{
                    value: Currency::new(57234234623612361),
                    address: address!("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"),
                }
            ],
            transactions: vec![
                v1::Transaction {
                    siacoin_inputs: vec![
                        v1::SiacoinInput{
                            parent_id: siacoin_id!("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c"),
                            unlock_conditions: v1::UnlockConditions::standard_unlock_conditions(public_key!("ed25519:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c")),
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
            ],
        };

        const BINARY_STR: &str = "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c90dc120000000000000000000000000001000000000000000700000000000000cb563bafbb55c90000000000000000000000000000000000000000000000000000000000000000010000000000000001000000000000008fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c000000000000000001000000000000006564323535313900000000000000000020000000000000008fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c010000000000000001000000000000000700000000000000f11318f74d10cf000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let mut serialized = Vec::new();
        b.encode_v1(&mut serialized).unwrap();
        assert_eq!(serialized, hex::decode(BINARY_STR).unwrap());
        let deserialized = Block::decode_v1(&mut &serialized[..]).unwrap();
        assert_eq!(deserialized, b);

        const JSON_STR: &str = "{\"parentID\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c\",\"nonce\":1236112,\"timestamp\":\"1970-01-01T00:00:00Z\",\"minerPayouts\":[{\"value\":\"57234234623612361\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}],\"transactions\":[{\"siacoinInputs\":[{\"parentID\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c\",\"unlockConditions\":{\"timelock\":0,\"publicKeys\":[\"ed25519:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c\"],\"signaturesRequired\":1}}],\"siacoinOutputs\":[{\"value\":\"67856467336433871\",\"address\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"}]}]}";
        let serialized = serde_json::to_string(&b).unwrap();
        assert_eq!(serialized, JSON_STR);
        let deserialized: Block = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, b);
    }

    #[test]
    fn test_transaction_derive() {
        const TXN_JSON: &str = r#"{"siacoinInputs":[{"parentID":"750d22eff727689d1d8d1c83e513a30bb68ee7f9125a4dafc882459e34c2069d","unlockConditions":{"timelock":0,"publicKeys":["ed25519:800ed6c2760e3e4ba1ff00128585c8cf8fed2e3dc1e3da1eb92d49f405bd6360"],"signaturesRequired":6312611591377486220}}],"siacoinOutputs":[{"value":"890415399000000000000000000000000","address":"480a064b5fca13002a7fe575845154bbf0b3af4cc4f147cbed387d43cce3568ae2497366eaa7"}],"fileContracts":[{"filesize":0,"fileMerkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","windowStart":10536451586783908586,"windowEnd":9324702155635244357,"payout":"0","validProofOutputs":[{"value":"1933513214000000000000000000000000","address":"944524fff2c49c401e748db37cfda7569fa6df35b704fe716394f2ac3f40ce87b4506e9906f0"}],"missedProofOutputs":[{"value":"2469287901000000000000000000000000","address":"1df67838262d7109ffcd9018f183b1eb33f05659a274b89ea6b52ff3617d34a770e9dd071d2e"}],"unlockHash":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69","revisionNumber":9657412421282982780}],"fileContractRevisions":[{"parentID":"e4e26d93771d3bbb3d9dd306105d77cfb3a6254d1cc3495903af6e013442c63c","unlockConditions":{"timelock":0,"publicKeys":["ed25519:e6b9cde4eb058f8ecbb083d99779cb0f6d518d5386f019af6ead09fa52de8567"],"signaturesRequired":206644730660526450},"revisionNumber":10595710523108536025,"filesize":0,"fileMerkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","windowStart":4348934140507359445,"windowEnd":14012366839994454386,"validProofOutputs":[{"value":"2435858510000000000000000000000000","address":"543bc0eda69f728d0a0fbce08e5bfc5ed7b961300e0af226949e135f7d12e32f0544e5262d6f"}],"missedProofOutputs":[{"value":"880343701000000000000000000000000","address":"7b7f9aee981fe0d93bb3f49c6233cf847ebdd39d7dc5253f7fc330df2167073b35f035703237"}],"unlockHash":"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"}],"storageProofs":[{"parentID":"c0b9e98c9e03a2740c75d673871c1ee91f36d1bb329ff3ddbf1dfa8c6e1a64eb","leaf":"b78fa521dc62d9ced82bc3b61e0aa5a5c221d6cca5db63d94c9879543fb98c0a971094a89cd4408487ae32902248d321b545f9a051729aa0bb1725b848e3d453","proof":["fe08c0a061475e7e5dec19e717cf98792fa7b555d0b5d3540a05db09f59ab8de"]}],"minerFees":["241119475000000000000000000000000"],"arbitraryData":["2shzIHEUJYwuNHz6c/gPz+aTEWZRTpDTmemX9yYAKlY="],"signatures":[{"parentID":"06d1fca03c5ddd9b09116db1b97c5451f7dc792b05362969f83e3e8dc1007f46","publicKeyIndex":6088345341283457116,"timelock":2014247885072555224,"coveredFields":{"wholeTransaction":true},"signature":"2XNEKGZrl9RhMa2JmGsvcmqQWAIX/uxtMwLnPI6VJPcXqub6qYIuoAThYp9NAwadk+1GG6CXC66g4rOjFYuNSA=="}]}"#;

        const EXPECTED_TRANSACTION_ID: TransactionID =
            transaction_id!("71a10d363f4af09c3fbce499b725067b0b19afe2bc9a8236704e85256f3244a6");
        const EXPECTED_SIACOIN_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("ea315efdd5914c54e8082d0de90b5afa9d4b92103d60661ec86b2a095413d836");
        const EXPECTED_SIAFUND_OUTPUT_ID: SiafundOutputID =
            siafund_id!("a8190ea7b4d41e08f45f27653b882faf8ff9fd57bb098d7022f105ef142279ec");
        const EXPECTED_FILE_CONTRACT_ID: FileContractID =
            contract_id!("ff7102bb111a64c7ff8a3cd68dbc962a03a8943065c3852a359662c8935fa979");

        let txn: v1::Transaction =
            serde_json::from_str(TXN_JSON).expect("transaction to deserialize");

        assert_eq!(txn.id(), EXPECTED_TRANSACTION_ID, "transaction id");

        assert_eq!(
            txn.siacoin_output_id(678569214627704587),
            EXPECTED_SIACOIN_OUTPUT_ID,
            "siacoin output id"
        );

        assert_eq!(
            txn.siafund_output_id(8940170890223196046),
            EXPECTED_SIAFUND_OUTPUT_ID,
            "siafund output id"
        );

        assert_eq!(
            txn.file_contract_id(3470616158951613631),
            EXPECTED_FILE_CONTRACT_ID,
            "file contract id"
        );
    }

    #[test]
    fn test_transaction_id_v2_derive() {
        const EXPECTED_V2_SIACOIN_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("f74e0d8eae89ec820184c9bacfcad0181c781c02020f8a3fcbc82fd4ebf2fcf0");
        const EXPECTED_V2_SIAFUND_OUTPUT_ID: SiafundOutputID =
            siafund_id!("f7d9ad77bfe9a102ef9590f97024f3aa8f54877d10447c128b52d5ca18cca983");
        const EXPECTED_V2_FILE_CONTRACT_ID: FileContractID =
            contract_id!("c67764bc06df3dd933e0d4e93c6f7cbe5b56670d1baae156b578d417f08e65cf");

        let txn_id =
            transaction_id!("168ecf3133ae713c26f90fe1790fb7536f12cc2a492985627856b77c6ad99070");

        assert_eq!(
            txn_id.v2_siacoin_output_id(3543556734851495409),
            EXPECTED_V2_SIACOIN_OUTPUT_ID,
            "v2 siacoin output id"
        );

        assert_eq!(
            txn_id.v2_siafund_output_id(4957302981402025980),
            EXPECTED_V2_SIAFUND_OUTPUT_ID,
            "v2 siafund output id"
        );

        assert_eq!(
            txn_id.v2_file_contract_id(5375460735837768427),
            EXPECTED_V2_FILE_CONTRACT_ID,
            "v2 file contract id"
        );
    }

    #[test]
    fn test_block_id_derive() {
        const EXPECTED_FOUNDATION_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("159e2c4159a112ea9a70242d541a26f49fce41b6126f9105eab9b68dba4cfafb");
        const EXPECTED_MINER_OUTPUT_ID: SiacoinOutputID =
            siacoin_id!("69e68779991392663d808276e6661d94628632354e258d8ab6724de1d9ca6208");

        let block_id =
            block_id!("c56d879b07b27fab3bdd06b833dbd1ad7eb167058851f543a517308b634a80a1");

        assert_eq!(
            block_id.foundation_output_id(),
            EXPECTED_FOUNDATION_OUTPUT_ID,
            "foundation output id"
        );

        assert_eq!(
            block_id.miner_output_id(3072616177397065894),
            EXPECTED_MINER_OUTPUT_ID,
            "miner output id"
        );
    }

    #[test]
    fn test_siafund_output_id_derive() {
        const EXPECTED_CLAIM_ID: SiacoinOutputID =
            siacoin_id!("8eec57722c2ac040e34322ba77cb6b488ac8081f856d93bea1bf1bef42aeaabb");
        const EXPECTED_V2_CLAIM_ID: SiacoinOutputID =
            siacoin_id!("b949006c65c70b5973da46cc783981d701dd854316e7efb1947c0b5f2fdc8db4");

        let siafund_output_id =
            siafund_id!("58ea19fd87ae5e10f928035e1021c3d9ee091fb3c0bbd5a1a6af41eea12e0f85");

        assert_eq!(
            siafund_output_id.claim_output_id(),
            EXPECTED_CLAIM_ID,
            "claim output id"
        );

        assert_eq!(
            siafund_output_id.v2_claim_output_id(),
            EXPECTED_V2_CLAIM_ID,
            "v2 claim output id"
        );
    }
}
