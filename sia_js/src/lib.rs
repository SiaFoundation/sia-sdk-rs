use getrandom::getrandom;
use js_sys::Array;
use sia::types::{v1, v2, Address, Currency, Hash256};
use utils::*;
use wasm_bindgen::prelude::*;

mod utils;

#[wasm_bindgen]
pub struct Seed(sia::seed::Seed);

#[wasm_bindgen]
pub struct PrivateKey(sia::signing::PrivateKey);

#[wasm_bindgen]
impl PrivateKey {
    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    pub fn sign_hash(&self, v: Vec<u8>) -> Result<Vec<u8>, JsError> {
        if v.len() != 32 {
            return Err(JsError::new("hash must be 32 bytes"));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(v.as_ref());
        let h = Hash256::from(b);
        Ok(self.0.sign_hash(&h).as_ref().to_vec())
    }
}

#[wasm_bindgen]
impl Seed {
    #[wasm_bindgen(constructor)]
    pub fn new(s: String) -> Result<Seed, JsError> {
        let seed =
            sia::seed::Seed::from_mnemonic(&s).map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(Seed(seed))
    }

    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_mnemonic()
    }

    #[wasm_bindgen]
    pub fn generate() -> Self {
        let mut entropy = [0u8; 16];
        getrandom(&mut entropy).unwrap();
        Seed(sia::seed::Seed::new(entropy))
    }

    #[wasm_bindgen(js_name = "privateKey")]
    pub fn private_key(&self, index: usize) -> PrivateKey {
        PrivateKey(self.0.private_key(index as u64))
    }
}

// TODO: define custom typescript generation to get rid of Array<any>
#[wasm_bindgen(inspectable)]
#[derive(Default)]
pub struct UnlockConditions {
    pub timelock: u64,
    #[wasm_bindgen(js_name = "publicKeys", getter_with_clone)]
    pub public_keys: Array,
    #[wasm_bindgen(js_name = "signaturesRequired")]
    pub signatures_required: u64,
}

#[wasm_bindgen]
impl UnlockConditions {
    #[wasm_bindgen(constructor)]
    pub fn new(v: JsValue) -> Result<Self, JsError> {
        if v.is_undefined() {
            Ok(Self::default())
        } else {
            let uc: v1::UnlockConditions = serde_wasm_bindgen::from_value(v)?;
            Ok(UnlockConditions {
                timelock: uc.timelock,
                public_keys: vec_to_js_array(uc.public_keys)?,
                signatures_required: uc.signatures_required,
            })
        }
    }

    fn to_rust(&self) -> Result<v1::UnlockConditions, JsError> {
        Ok(v1::UnlockConditions {
            timelock: 0,
            public_keys: serde_wasm_bindgen::from_value(self.public_keys.clone().into())?,
            signatures_required: 0,
        })
    }

    #[wasm_bindgen(js_name = "address")]
    pub fn address(&self) -> Result<String, JsError> {
        let uc = self.to_rust()?;
        Ok(uc.address().to_string())
    }
}

// TODO: define custom typescript generation to get rid of Array<any>
#[wasm_bindgen(getter_with_clone, inspectable)]
#[derive(Default)]
pub struct Transaction {
    pub siacoin_inputs: Array,
    pub siacoin_outputs: Array,
    pub file_contracts: Array,
    pub file_contract_revisions: Array,
    pub storage_proofs: Array,
    pub siafund_inputs: Array,
    pub siafund_outputs: Array,
    pub miner_fees: Array,
    pub arbitrary_data: Array,
    pub signatures: Array,
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(constructor)]
    pub fn new(v: JsValue) -> Result<Self, JsError> {
        if v.is_undefined() {
            Ok(Transaction::default())
        } else {
            let txn: v1::Transaction = serde_wasm_bindgen::from_value(v)?;
            Ok(Transaction {
                siacoin_inputs: vec_to_js_array(txn.siacoin_inputs)?,
                siacoin_outputs: vec_to_js_array(txn.siacoin_outputs)?,
                file_contracts: vec_to_js_array(txn.file_contracts)?,
                file_contract_revisions: vec_to_js_array(txn.file_contract_revisions)?,
                storage_proofs: vec_to_js_array(txn.storage_proofs)?,
                siafund_inputs: vec_to_js_array(txn.siafund_inputs)?,
                siafund_outputs: vec_to_js_array(txn.siafund_outputs)?,
                miner_fees: vec_to_js_array(txn.miner_fees)?,
                arbitrary_data: vec_to_js_array(txn.arbitrary_data)?,
                signatures: vec_to_js_array(txn.signatures)?,
            })
        }
    }

    fn to_rust(&self) -> Result<v1::Transaction, JsError> {
        Ok(v1::Transaction {
            siacoin_inputs: serde_wasm_bindgen::from_value(self.siacoin_inputs.clone().into())?,
            siacoin_outputs: serde_wasm_bindgen::from_value(self.siacoin_outputs.clone().into())?,
            file_contracts: serde_wasm_bindgen::from_value(self.file_contracts.clone().into())?,
            file_contract_revisions: serde_wasm_bindgen::from_value(
                self.file_contract_revisions.clone().into(),
            )?,
            storage_proofs: serde_wasm_bindgen::from_value(self.storage_proofs.clone().into())?,
            siafund_inputs: serde_wasm_bindgen::from_value(self.siafund_inputs.clone().into())?,
            siafund_outputs: serde_wasm_bindgen::from_value(self.siafund_outputs.clone().into())?,
            miner_fees: serde_wasm_bindgen::from_value(self.miner_fees.clone().into())?,
            arbitrary_data: serde_wasm_bindgen::from_value(self.arbitrary_data.clone().into())?,
            signatures: serde_wasm_bindgen::from_value(self.signatures.clone().into())?,
        })
    }

    #[wasm_bindgen(js_name = id)]
    pub fn id(&self) -> Result<String, JsError> {
        let txn = self.to_rust()?;
        Ok(txn.id().to_string())
    }

    #[wasm_bindgen(js_name = "siacoinOutputID")]
    pub fn siacoin_output_id(&self, index: usize) -> Result<String, JsError> {
        let txn = self.to_rust()?;
        Ok(txn.siacoin_output_id(index).to_string())
    }

    #[wasm_bindgen(js_name = "siafundOutputID")]
    pub fn siafund_output_id(&self, index: usize) -> Result<String, JsError> {
        let txn = self.to_rust()?;
        Ok(txn.siafund_output_id(index).to_string())
    }

    #[wasm_bindgen(js_name = "fileContractID")]
    pub fn file_contract_id(&self, index: usize) -> Result<String, JsError> {
        let txn = self.to_rust()?;
        Ok(txn.file_contract_id(index).to_string())
    }
}

#[wasm_bindgen(getter_with_clone, inspectable)]
#[derive(Default)]
pub struct V2Transaction {
    pub siacoin_inputs: Array,
    pub siacoin_outputs: Array,
    pub siafund_inputs: Array,
    pub siafund_outputs: Array,
    pub file_contracts: Array,
    pub file_contract_revisions: Array,
    pub file_contract_resolutions: Array,
    pub attestations: Array,
    pub arbitrary_data: Vec<u8>,
    pub new_foundation_address: Option<String>,
    pub miner_fee: u128,
}

#[wasm_bindgen]
impl V2Transaction {
    #[wasm_bindgen(constructor)]
    pub fn new(v: JsValue) -> Result<Self, JsError> {
        if v.is_undefined() {
            Ok(V2Transaction::default())
        } else {
            let txn: v2::Transaction = serde_wasm_bindgen::from_value(v)?;
            Ok(V2Transaction {
                siacoin_inputs: vec_to_js_array(txn.siacoin_inputs)?,
                siacoin_outputs: vec_to_js_array(txn.siacoin_outputs)?,
                siafund_inputs: vec_to_js_array(txn.siafund_inputs)?,
                siafund_outputs: vec_to_js_array(txn.siafund_outputs)?,
                file_contracts: vec_to_js_array(txn.file_contracts)?,
                file_contract_revisions: vec_to_js_array(txn.file_contract_revisions)?,
                file_contract_resolutions: vec_to_js_array(txn.file_contract_resolutions)?,
                attestations: vec_to_js_array(txn.attestations)?,
                arbitrary_data: txn.arbitrary_data,
                new_foundation_address: txn.new_foundation_address.map(|a| a.to_string()),
                miner_fee: *txn.miner_fee,
            })
        }
    }

    fn to_rust(&self) -> Result<v2::Transaction, JsError> {
        Ok(v2::Transaction {
            siacoin_inputs: serde_wasm_bindgen::from_value(self.siacoin_inputs.clone().into())?,
            siacoin_outputs: serde_wasm_bindgen::from_value(self.siacoin_outputs.clone().into())?,
            siafund_inputs: serde_wasm_bindgen::from_value(self.siafund_inputs.clone().into())?,
            siafund_outputs: serde_wasm_bindgen::from_value(self.siafund_outputs.clone().into())?,
            file_contracts: serde_wasm_bindgen::from_value(self.file_contracts.clone().into())?,
            file_contract_revisions: serde_wasm_bindgen::from_value(
                self.file_contract_revisions.clone().into(),
            )?,
            file_contract_resolutions: serde_wasm_bindgen::from_value(
                self.file_contract_resolutions.clone().into(),
            )?,
            attestations: serde_wasm_bindgen::from_value(self.attestations.clone().into())?,
            arbitrary_data: self.arbitrary_data.clone(),
            new_foundation_address: match &self.new_foundation_address {
                Some(a) => Some(
                    Address::parse_string(a)
                        .map_err(|_| JsError::new("invalid new foundation address"))?,
                ),
                None => None,
            },
            miner_fee: Currency::new(self.miner_fee),
        })
    }

    pub fn id(&self) -> Result<String, JsError> {
        let txn = self.to_rust()?;
        Ok(txn.id().to_string())
    }
}
