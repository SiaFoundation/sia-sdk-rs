use core::fmt;

use crate::Signature;
use crate::Currency;
use crate::{Address, UnlockConditions};
use crate::{HexParseError, Hash256, SiaEncodable};
use blake2b_simd::{Params, State};

const SIACOIN_OUTPUT_ID_PREFIX : [u8;16] = [b's', b'i', b'a', b'c', b'o', b'i', b'n', b' ', b'o', b'u', b't', b'p', b'u', b't', 0, 0];
const SIAFUND_OUTPUT_ID_PREFIX : [u8;16] = [b's', b'i', b'a', b'f', b'u', b'n', b'd', b' ', b'o', b'u', b't', b'p', b'u', b't', 0, 0];

#[derive(Debug, Clone, Copy)]
pub struct SiacoinOutputID([u8;32]);

impl SiacoinOutputID {
	pub fn new(data: [u8;32]) -> Self {
		SiacoinOutputID(data)
	}

	pub fn as_bytes(&self) -> [u8;32] {
		self.0
	}

	pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
		let s = match s.split_once(":"){
			Some((_prefix, suffix)) => suffix,
			None => s
		};

		if s.len() != 64 {
		 	return Err(HexParseError::InvalidLength);
		}

		let mut data = [0u8; 32];
		hex::decode_to_slice(s, &mut data).map_err(|err| HexParseError::HexError(err))?;
		Ok(SiacoinOutputID(data))
	}
}

impl SiaEncodable for SiacoinOutputID {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.0);
	}
}

impl fmt::Display for SiacoinOutputID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "scoid:{}", hex::encode(&self.0))
	}
}

#[derive(Debug, Clone)]
pub struct SiacoinInput {
	pub parent_id: SiacoinOutputID,
	pub unlock_conditions: UnlockConditions,
}

impl SiaEncodable for SiacoinInput {
	fn encode(&self, buf: &mut Vec<u8>) {
		self.parent_id.encode(buf);
		self.unlock_conditions.encode(buf);
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SiacoinOutput {
	pub address: Address,
	pub value: Currency,
}

impl SiaEncodable for SiacoinOutput {
	fn encode(&self, buf: &mut Vec<u8>) {
		self.value.encode(buf);
		self.address.encode(buf);
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SiafundOutputID([u8;32]);

impl SiafundOutputID {
	pub fn as_bytes(&self) -> [u8;32] {
		self.0
	}

	pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
		let s = match s.split_once(":"){
			Some((_prefix, suffix)) => suffix,
			None => s
		};

		if s.len() != 64 {
		 	return Err(HexParseError::InvalidLength);
		}

		let mut data = [0u8; 32];
		hex::decode_to_slice(s, &mut data).map_err(|err| HexParseError::HexError(err))?;
		Ok(SiafundOutputID(data))
	}
}

impl fmt::Display for SiafundOutputID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "sfoid:{}", hex::encode(&self.0))
	}
}

impl SiaEncodable for SiafundOutputID {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.0);
	}
}

#[derive(Debug, Clone)]
pub struct SiafundInput {
	pub parent_id: SiafundOutputID,
	pub unlock_conditions: UnlockConditions,
	pub claim_address: Address,
}

impl SiaEncodable for SiafundInput {
	fn encode(&self, buf: &mut Vec<u8>) {
		self.parent_id.encode(buf);
		self.unlock_conditions.encode(buf);
		self.claim_address.encode(buf);
	}
}

#[derive(Debug, Clone, Copy)]
pub struct SiafundOutput {
	pub address: Address, 
	pub value: Currency,
	pub claim_start: Currency,
}

impl SiaEncodable for SiafundOutput {
	fn encode(&self, buf: &mut Vec<u8>) {
		self.value.encode(buf);
		self.address.encode(buf);
		self.claim_start.encode(buf);
	}
}

#[derive(Debug, Clone, Copy)]
pub struct FileContractID([u8;32]);

impl FileContractID {
	pub fn as_bytes(&self) -> [u8;32] {
		self.0
	}

	pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
		let s = match s.split_once(":"){
			Some((_prefix, suffix)) => suffix,
			None => s
		};

		if s.len() != 64 {
		 	return Err(HexParseError::InvalidLength);
		}

		let mut data = [0u8; 32];
		hex::decode_to_slice(s, &mut data).map_err(|err| HexParseError::HexError(err))?;
		Ok(FileContractID(data))
	}
}

impl fmt::Display for FileContractID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "fcid:{}", hex::encode(&self.0))
	}
}

#[derive(Debug, Clone)]
pub struct FileContract {
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

impl SiaEncodable for FileContract {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.file_size.to_le_bytes());
		buf.extend_from_slice(&self.file_merkle_root.as_bytes());
		buf.extend_from_slice(&self.window_start.to_le_bytes());
		buf.extend_from_slice(&self.window_end.to_le_bytes());
		self.payout.encode(buf);
		buf.extend_from_slice(&(self.valid_proof_outputs.len() as u64).to_le_bytes());
		for output in &self.valid_proof_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&(self.missed_proof_outputs.len() as u64).to_le_bytes());
		for output in &self.missed_proof_outputs {
			output.encode(buf);
		}
		self.unlock_hash.encode(buf);
		buf.extend_from_slice(&self.revision_number.to_le_bytes());
	}
}

#[derive(Debug, Clone)]
pub struct FileContractRevision {
	pub parent_id: FileContractID,
	pub unlock_conditions: UnlockConditions,
	pub revision_number: u64,
	pub file_size: u64,
	pub file_merkle_root: Hash256,
	pub window_start: u64,
	pub window_end: u64,
	pub valid_proof_outputs: Vec<SiacoinOutput>,
	pub missed_proof_outputs: Vec<SiacoinOutput>,
	pub unlock_hash: Address,
}

impl SiaEncodable for FileContractRevision {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		self.unlock_conditions.encode(buf);
		buf.extend_from_slice(&self.revision_number.to_le_bytes());
		buf.extend_from_slice(&self.file_size.to_le_bytes());
		buf.extend_from_slice(&self.file_merkle_root.as_bytes());
		buf.extend_from_slice(&self.window_start.to_le_bytes());
		buf.extend_from_slice(&self.window_end.to_le_bytes());
		buf.extend_from_slice(&(self.valid_proof_outputs.len() as u64).to_le_bytes());
		for output in &self.valid_proof_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&(self.missed_proof_outputs.len() as u64).to_le_bytes());
		for output in &self.missed_proof_outputs {
			output.encode(buf);
		}
		self.unlock_hash.encode(buf);
	}
}

#[derive(Debug, Clone)]
pub struct StorageProof {
	pub parent_id: FileContractID,
	pub leaf: [u8;64],
	pub proof: Vec<Hash256>,
}

impl SiaEncodable for StorageProof {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		buf.extend_from_slice(&self.leaf);
		buf.extend_from_slice(&(self.proof.len() as u64).to_le_bytes());
		for proof in &self.proof {
			buf.extend_from_slice(&proof.as_bytes());
		}
	}
}

#[derive(Debug, Clone)]
pub struct CoveredFields {
	pub whole_transaction: bool,
	pub siacoin_inputs: Vec<u64>,
	pub siacoin_outputs: Vec<u64>,
	pub siafund_inputs: Vec<u64>,
	pub siafund_outputs: Vec<u64>,
	pub file_contracts: Vec<u64>,
	pub file_contract_revisions: Vec<u64>,
	pub storage_proofs: Vec<u64>,
	pub miner_fees: Vec<u64>,
	pub arbitrary_data: Vec<u64>,
	pub signatures: Vec<u64>,
}

impl SiaEncodable for CoveredFields {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.push(self.whole_transaction as u8);
		buf.extend_from_slice(&(self.siacoin_inputs.len() as u64).to_le_bytes());
		for input in &self.siacoin_inputs {
			buf.extend_from_slice(&input.to_le_bytes());
		}
		buf.extend_from_slice(&(self.siacoin_outputs.len() as u64).to_le_bytes());
		for output in &self.siacoin_outputs {
			buf.extend_from_slice(&output.to_le_bytes());
		}
		buf.extend_from_slice(&(self.siafund_inputs.len() as u64).to_le_bytes());
		for input in &self.siafund_inputs {
			buf.extend_from_slice(&input.to_le_bytes());
		}
		buf.extend_from_slice(&(self.siafund_outputs.len() as u64).to_le_bytes());
		for output in &self.siafund_outputs {
			buf.extend_from_slice(&output.to_le_bytes());
		}
		buf.extend_from_slice(&(self.file_contracts.len() as u64).to_le_bytes());
		for file_contract in &self.file_contracts {
			buf.extend_from_slice(&file_contract.to_le_bytes());
		}
		buf.extend_from_slice(&(self.file_contract_revisions.len() as u64).to_le_bytes());
		for file_contract_revision in &self.file_contract_revisions {
			buf.extend_from_slice(&file_contract_revision.to_le_bytes());
		}
		buf.extend_from_slice(&(self.storage_proofs.len() as u64).to_le_bytes());
		for storage_proof in &self.storage_proofs {
			buf.extend_from_slice(&storage_proof.to_le_bytes());
		}
		buf.extend_from_slice(&(self.miner_fees.len() as u64).to_le_bytes());
		for miner_fee in &self.miner_fees {
			buf.extend_from_slice(&miner_fee.to_le_bytes());
		}
		buf.extend_from_slice(&(self.arbitrary_data.len() as u64).to_le_bytes());
		for arbitrary_data in &self.arbitrary_data {
			buf.extend_from_slice(&arbitrary_data.to_le_bytes());
		}
		buf.extend_from_slice(&(self.signatures.len() as u64).to_le_bytes());
		for signature in &self.signatures {
			buf.extend_from_slice(&signature.to_le_bytes());
		}
	}
}

#[derive(Debug, Clone)]
pub struct TransactionSignature {
	pub parent_id: Hash256,
	pub public_key_index: u64,
	pub timelock: u64,
	pub covered_fields: CoveredFields,
	pub signature: Signature,
}

impl SiaEncodable for TransactionSignature {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		buf.extend_from_slice(&self.public_key_index.to_le_bytes());
		buf.extend_from_slice(&self.timelock.to_le_bytes());
		self.covered_fields.encode(buf);
		self.signature.encode(buf);
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TransactionID([u8;32]);

impl TransactionID {
	pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
		let s = match s.split_once(":"){
			Some((_prefix, suffix)) => suffix,
			None => s
		};

		if s.len() != 64 {
		 	return Err(HexParseError::InvalidLength);
		}

		let mut data = [0u8; 32];
		hex::decode_to_slice(s, &mut data).map_err(|err| HexParseError::HexError(err))?;
		Ok(TransactionID(data))
	}
}

impl fmt::Display for TransactionID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "txn:{}", hex::encode(&self.0))
	}
}

#[derive(Default, Debug, Clone)]
pub struct Transaction {
	pub miner_fees: Vec<Currency>,
	pub siacoin_inputs: Vec<SiacoinInput>,
	pub siacoin_outputs: Vec<SiacoinOutput>,
	pub siafund_inputs: Vec<SiafundInput>,
	pub siafund_outputs: Vec<SiafundOutput>,
	pub file_contracts: Vec<FileContract>,
	pub file_contract_revisions: Vec<FileContractRevision>,
	pub storage_proofs: Vec<StorageProof>,
	pub signatures: Vec<TransactionSignature>,
	pub arbitrary_data: Vec<Vec<u8>>,
}

impl Transaction {
	pub fn encode_no_sigs(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		
		buf.extend_from_slice(&(self.siacoin_inputs.len() as u64).to_le_bytes());
		for input in &self.siacoin_inputs {
			input.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.siacoin_outputs.len() as u64).to_le_bytes());
		for output in &self.siacoin_outputs {
			output.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.file_contracts.len() as u64).to_le_bytes());
		for file_contract in &self.file_contracts {
			file_contract.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.file_contract_revisions.len() as u64).to_le_bytes());
		for file_contract_revision in &self.file_contract_revisions {
			file_contract_revision.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.storage_proofs.len() as u64).to_le_bytes());
		for storage_proof in &self.storage_proofs {
			storage_proof.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.siafund_inputs.len() as u64).to_le_bytes());
		for input in &self.siafund_inputs {
			input.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.siafund_outputs.len() as u64).to_le_bytes());
		for output in &self.siafund_outputs {
			output.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.miner_fees.len() as u64).to_le_bytes());
		for fee in &self.miner_fees {
			fee.encode(&mut buf);
		}

		buf.extend_from_slice(&(self.arbitrary_data.len() as u64).to_le_bytes());
		for data in &self.arbitrary_data {
			buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
			buf.extend_from_slice(data);
		}
		return buf;
	}
	pub fn hash_no_sigs(&self, state: &mut State) {
		state.update(&(self.siacoin_inputs.len() as u64).to_le_bytes());
		let mut buf = Vec::new();
		for input in self.siacoin_inputs.iter() {
			buf.clear();
			input.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.siacoin_outputs.len() as u64).to_le_bytes());
		for output in self.siacoin_outputs.iter() {
			buf.clear();
			output.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.file_contracts.len() as u64).to_le_bytes());
		for file_contract in self.file_contracts.iter() {
			buf.clear();
			file_contract.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.file_contract_revisions.len() as u64).to_le_bytes());
		for file_contract_revision in self.file_contract_revisions.iter() {
			buf.clear();
			file_contract_revision.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.storage_proofs.len() as u64).to_le_bytes());
		for storage_proof in self.storage_proofs.iter() {
			buf.clear();
			storage_proof.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.siafund_inputs.len() as u64).to_le_bytes());
		for input in self.siafund_inputs.iter() {
			buf.clear();
			input.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.siafund_outputs.len() as u64).to_le_bytes());
		for output in self.siafund_outputs.iter() {
			buf.clear();
			output.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.miner_fees.len() as u64).to_le_bytes());
		for fee in self.miner_fees.iter() {
			buf.clear();
			fee.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&(self.arbitrary_data.len() as u64).to_le_bytes());
		for data in self.arbitrary_data.iter() {
			state.update(&(data.len() as u64).to_le_bytes());
			state.update(&data);
		}
	}

	pub fn id(&self) -> TransactionID {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();
		self.hash_no_sigs(&mut state);
		let hash = state.finalize();
		let buf = hash.as_bytes();

		TransactionID(buf
			.try_into()
			.unwrap())
	}

	pub fn siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		state.update(&SIACOIN_OUTPUT_ID_PREFIX);
		self.hash_no_sigs(&mut state);

		SiacoinOutputID(state.update(&i.to_le_bytes())
			.finalize()
			.as_bytes()
			.try_into()
			.unwrap())
	}

	pub fn siafund_output_id(&self, i: usize) -> SiafundOutputID {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		state.update(&SIAFUND_OUTPUT_ID_PREFIX);
		self.hash_no_sigs(&mut state);

		SiafundOutputID(state.update(&i.to_le_bytes())
			.finalize()
			.as_bytes()
			.try_into()
			.unwrap())
	}
}

impl SiaEncodable for Transaction {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&(self.siacoin_inputs.len() as u64).to_le_bytes());
		for input in &self.siacoin_inputs {
			input.encode(buf);
		}
		buf.extend_from_slice(&(self.siacoin_outputs.len() as u64).to_le_bytes());
		for output in &self.siacoin_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&(self.file_contracts.len() as u64).to_le_bytes());
		for file_contract in &self.file_contracts {
			file_contract.encode(buf);
		}
		buf.extend_from_slice(&(self.file_contract_revisions.len() as u64).to_le_bytes());
		for file_contract_revision in &self.file_contract_revisions {
			file_contract_revision.encode(buf);
		}
		buf.extend_from_slice(&(self.storage_proofs.len() as u64).to_le_bytes());
		for storage_proof in &self.storage_proofs {
			storage_proof.encode(buf);
		}
		buf.extend_from_slice(&(self.siafund_inputs.len() as u64).to_le_bytes());
		for input in &self.siafund_inputs {
			input.encode(buf);
		}
		buf.extend_from_slice(&(self.siafund_outputs.len() as u64).to_le_bytes());
		for output in &self.siafund_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&(self.miner_fees.len() as u64).to_le_bytes());
		for fee in &self.miner_fees {
			fee.encode(buf);
		}
		buf.extend_from_slice(&(self.arbitrary_data.len() as u64).to_le_bytes());
		for data in &self.arbitrary_data {
			buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
			buf.extend_from_slice(data);
		}
		buf.extend_from_slice(&(self.signatures.len() as u64).to_le_bytes());
		for signature in &self.signatures {
			signature.encode(buf);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_transaction_id() {
		let txn = Transaction::default();
		assert_eq!(txn.id().to_string(), "txn:b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24")
	}

	#[test]
	fn test_txn_id() {
		let txn = Transaction::default();
		let h = Params::new()
		.hash_length(32)
		.to_state()
		.update(&txn.encode_no_sigs())
		.finalize();

		assert_eq!(txn.encode_no_sigs(), [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
		let buf = h.as_bytes();
		assert_eq!(hex::encode(&buf), "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24");
	}
}