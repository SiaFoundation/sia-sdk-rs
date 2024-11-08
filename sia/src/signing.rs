use core::fmt;
use std::time::SystemTime;

use crate::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::{ChainIndex, Hash256, HexParseError};
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::Error;
use serde::{Deserialize, Serialize};

/// An ed25519 public key that can be used to verify a signature
#[derive(Debug, PartialEq, Clone, Copy, SiaEncode, SiaDecode)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    const PREFIX: &'static str = "ed25519:";
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(
            &format!("{}{}", Self::PREFIX, &self.to_string()),
            serializer,
        )
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix(Self::PREFIX).ok_or(Error::custom(format!(
            "key must have prefix '{}'",
            Self::PREFIX
        )))?;
        let mut pk = [0; 32];
        hex::decode_to_slice(s, &mut pk).map_err(|e| Error::custom(format!("{:?}", e)))?;
        Ok(Self::new(pk))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl PublicKey {
    pub fn new(buf: [u8; 32]) -> Self {
        PublicKey(buf)
    }

    pub fn verify(&self, sig_hash: &Hash256, signature: &Signature) -> bool {
        let pk = VerifyingKey::from_bytes(&self.0).unwrap();
        pk.verify(
            sig_hash.as_ref(),
            &ED25519Signature::from_bytes(signature.as_ref()),
        )
        .is_ok()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An ed25519 private key that can be used to sign a hash
#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey([u8; 64]);

impl PrivateKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(seed);
        PrivateKey(sk.to_keypair_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[32..]);
        PublicKey::new(buf)
    }

    pub fn sign_hash(&self, h: &Hash256) -> Signature {
        let sk = SigningKey::from_bytes(&self.0[..32].try_into().unwrap());
        Signature::new(sk.sign(h.as_ref()).to_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 64]> for PrivateKey {
    fn from(key: [u8; 64]) -> Self {
        PrivateKey(key)
    }
}

impl From<Hash256> for PrivateKey {
    fn from(hash: Hash256) -> Self {
        PrivateKey::from_seed(hash.as_ref())
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zero out the private key
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SiaEncode, SiaDecode)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&hex::encode(self.0), serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = hex::decode(String::deserialize(deserializer)?)
            .map_err(|e| D::Error::custom(format!("{:?}", e)))?;
        if buf.len() != 64 {
            return Err(D::Error::custom("Invalid signature length"));
        }
        Ok(Signature(buf.try_into().unwrap()))
    }
}

impl Signature {
    pub fn new(sig: [u8; 64]) -> Self {
        Signature(sig)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let data = hex::decode(s).map_err(HexParseError::HexError)?;
        if data.len() != 64 {
            return Err(HexParseError::InvalidLength);
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data);
        Ok(Signature(sig))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0; 64])
    }
}

impl AsRef<[u8; 64]> for Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for Signature {
    fn from(buf: [u8; 64]) -> Self {
        Signature(buf)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Default, Debug)]
pub struct NetworkHardforks {
    pub asic_height: u64,

    pub foundation_height: u64,

    pub v2_allow_height: u64,
    pub v2_require_height: u64,
}

pub struct SigningState {
    pub index: ChainIndex,
    pub median_timestamp: SystemTime,
    pub hardforks: NetworkHardforks,
}

impl SigningState {
    pub fn new(
        index: ChainIndex,
        median_timestamp: SystemTime,
        hardforks: NetworkHardforks,
    ) -> Self {
        SigningState {
            index,
            median_timestamp,
            hardforks,
        }
    }

    pub fn replay_prefix(&self) -> &[u8] {
        if self.index.height >= self.hardforks.v2_allow_height {
            return &[2];
        } else if self.index.height >= self.hardforks.foundation_height {
            return &[1];
        } else if self.index.height >= self.hardforks.asic_height {
            return &[0];
        }
        &[]
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::transactions::{
        CoveredFields, FileContract, FileContractID, FileContractRevision, SiacoinInput,
        SiacoinOutput, SiafundInput, SiafundOutput, StorageProof, Transaction,
        TransactionSignature,
    };
    use crate::unlock_conditions::UnlockConditions;
    use crate::{Address, Currency, Leaf};

    use super::*;

    #[test]
    fn test_serialize_publickey() {
        let public_key_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let public_key = PublicKey::new(hex::decode(public_key_str).unwrap().try_into().unwrap());

        // binary
        let mut public_key_serialized = Vec::new();
        public_key.encode(&mut public_key_serialized).unwrap();
        assert_eq!(public_key_serialized, hex::decode(public_key_str).unwrap());
        let public_key_deserialized =
            PublicKey::decode(&mut public_key_serialized.as_slice()).unwrap();
        assert_eq!(public_key_deserialized, public_key);

        // json
        let public_key_serialized = serde_json::to_string(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            serde_json::from_str(&public_key_serialized).unwrap();
        assert_eq!(
            public_key_serialized,
            format!("\"ed25519:{0}\"", public_key_str)
        );
        assert_eq!(public_key_deserialized, public_key);
    }

    #[test]
    fn test_transaction_sign_verify() {
        let unsigned_transaction = Transaction {
            siacoin_inputs: vec![SiacoinInput {
                parent_id: Default::default(),
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![],
                    signatures_required: 0,
                },
            }],
            siacoin_outputs: vec![SiacoinOutput {
                value: Currency::new(0),
                address: Address::from([0u8; 32]),
            }],
            file_contracts: vec![FileContract {
                file_size: 0,
                file_merkle_root: Default::default(),
                window_start: 0,
                window_end: 0,
                payout: Currency::new(0),
                valid_proof_outputs: vec![],
                missed_proof_outputs: vec![],
                unlock_hash: Hash256::default(),
                revision_number: 0,
            }],
            file_contract_revisions: vec![FileContractRevision {
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![],
                    signatures_required: 0,
                },
                parent_id: Default::default(),
                revision_number: 0,
                file_size: 0,
                file_merkle_root: Default::default(),
                window_start: 0,
                window_end: 0,
                valid_proof_outputs: vec![],
                missed_proof_outputs: vec![],
                unlock_hash: Default::default(),
            }],
            storage_proofs: vec![StorageProof {
                parent_id: FileContractID::from([0u8; 32]),
                leaf: Leaf::from([0u8; 64]),
                proof: vec![],
            }],
            siafund_inputs: vec![SiafundInput {
                parent_id: Default::default(),
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![],
                    signatures_required: 0,
                },
                claim_address: Address::from([0u8; 32]),
            }],
            siafund_outputs: vec![SiafundOutput {
                value: 0,
                address: Address::from([0u8; 32]),
            }],
            miner_fees: vec![Currency::new(0)],
            arbitrary_data: vec![vec![1, 2, 3]],
            signatures: vec![TransactionSignature {
                parent_id: Default::default(),
                public_key_index: 0,
                timelock: 0,
                covered_fields: Default::default(),
                signature: Default::default(),
            }],
        };

        let key = PrivateKey::from([
            114, 152, 250, 154, 63, 214, 160, 97, 24, 74, 157, 172, 159, 191, 32, 141, 56, 178,
            117, 28, 166, 64, 121, 47, 18, 79, 248, 41, 232, 126, 231, 140, 94, 19, 124, 209, 145,
            85, 91, 26, 80, 172, 5, 203, 35, 91, 64, 126, 9, 173, 7, 54, 83, 206, 215, 33, 39, 150,
            60, 53, 203, 125, 192, 147,
        ]);

        let mut state = SigningState::new(
            ChainIndex {
                id: Default::default(),
                height: 1,
            },
            SystemTime::UNIX_EPOCH, // not relevant
            NetworkHardforks {
                asic_height: 10,
                foundation_height: 100,
                v2_allow_height: 1000,
                v2_require_height: 10000,
            },
        );

        // various test-cases for the individual hardfork heights
        struct TestCase {
            height: u64,
            whole_transaction: bool,
            sig_string: String,
        }
        let test_cases = [
            TestCase {
                height: 1,
                whole_transaction: true,
                sig_string: "eaeeea529878fc861ac77a6e64ea3faea35b0804f655f1f7a6486ddd5b10530621ec7b8fdcf23ad66f7405ab2345d63b570d3855540693977462aa466167c704".to_string(),
            },
            TestCase {
                height: 10,
                whole_transaction: true,
                sig_string: "50c2a831c57d71bbb4cdd91c50aa119f755ff52c85b695254df5e4f3fb6619e0b5120d1fb460d149d60d15e4fff81d6b05ba470ab0f9d63dbcd2d8b64b68810d".to_string(),
            },
			TestCase {
                height: 100,
                whole_transaction: true,
                sig_string: "edb9e4035e5d194b1cc94aaa1330850cef728fcc92d11d4c0ce8d65d7a6ce81ada8a39e3df3a0052ee452c34a43f2b13217b567a74ac0a30ee84e381854d9406".to_string(),
            },
            TestCase {
                height: 1000,
                whole_transaction: true,
                sig_string: "98fe8fb15bd788a6f43cf24f8de3b57556e01d66f87dd2649d7ff8c1e2d48a007468a6965a95ccd3db907128197e1f0e37735593176d610cca859717eac2fd05".to_string(),
            },
            TestCase {
                height: 10000,
                whole_transaction: true,
                sig_string: "98fe8fb15bd788a6f43cf24f8de3b57556e01d66f87dd2649d7ff8c1e2d48a007468a6965a95ccd3db907128197e1f0e37735593176d610cca859717eac2fd05".to_string(),
            },
            TestCase {
                height: 1,
                whole_transaction: false,
                sig_string: "1d2f0cda9aafbe3ac87b0facf7fdf40c322b7413291fe63c3971f962755fe71c35e638a56eb3a26199a5dbc09244d8a2e4311fc263b34b793772e95e2b663b01".to_string(),
            },
            TestCase {
                height: 10,
                whole_transaction: false,
                sig_string: "b0c3b86c36db9200ef6fecd31442652af277aa17859e895d8bf9ce517e93d1765a46eb13790aa6c06fa03df6d2be9032eaa965cccf79223c1fc7e8d4b8e3eb0a".to_string(),
            },
            TestCase {
                height: 100,
                whole_transaction: false,
                sig_string: "c6e1f4fee7b9c1a141d6780e61af883a669127f5fa7569a7b69d1b88d434c0336690075b0a5048aba3be2b81751430f0229a3e6e7fcdd3c080ac7435a0c4500d".to_string(),
            },
            TestCase {
                height: 1000,
                whole_transaction: false,
                sig_string: "c1547a6f8193329f00dd3409ef3f3d2df961cf606075eef28fe2d87ff446baa3ac7ae65e1773e40c5bef5f1d9452a6ec3d78579dea20b544c5f8f672ee96130f".to_string(),
            },
            TestCase {
                height: 10000,
                whole_transaction: false,
                sig_string: "c1547a6f8193329f00dd3409ef3f3d2df961cf606075eef28fe2d87ff446baa3ac7ae65e1773e40c5bef5f1d9452a6ec3d78579dea20b544c5f8f672ee96130f".to_string(),
            },
        ];

        for tc in test_cases {
            // update state
            state.index.height = tc.height;

            // covered fields are either the whole transaction or all fields
            let covered_fields = if tc.whole_transaction {
                CoveredFields::whole_transaction()
            } else {
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![0],
                    siacoin_outputs: vec![0],
                    file_contracts: vec![0],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![0],
                    siafund_inputs: vec![0],
                    siafund_outputs: vec![0],
                    miner_fees: vec![0],
                    arbitrary_data: vec![0],
                    signatures: vec![0],
                }
            };

            // sign and check signature
            let signature = unsigned_transaction
                .sign(&state, &covered_fields, Hash256::default(), 1, 100, &key)
                .unwrap();
            assert_eq!(
                hex::encode(signature.signature.clone()),
                tc.sig_string,
                "height: {}",
                tc.height
            );

            // manually build the sig_hash and check the signature
            let sig_hash = if tc.whole_transaction {
                unsigned_transaction
                    .whole_sig_hash(&state, &Hash256::default(), 1, 100, &Vec::new())
                    .unwrap()
            } else {
                unsigned_transaction
                    .partial_sig_hash(&state, &covered_fields)
                    .unwrap()
            };
            let sig = Signature::new(signature.signature.try_into().unwrap());
            assert!(
                key.public_key().verify(&sig_hash, &sig),
                "height: {}",
                tc.height
            );
        }
    }
}
