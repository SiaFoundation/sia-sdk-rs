//! Generate pre-authorized keys and sign indexd creation requests.

use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sia_core::encoding::SiaEncodable;
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::Hash256;

/// An unsigned request to create a pre-authorized key in indexd.
pub struct PreAuthorizedKeyRequest {
    /// The connect key used to authorize connections.
    pub connect_key: String,
    /// When the authorization expires.
    pub expiration: DateTime<Utc>,
    /// The maximum number of authorized connections.
    pub total_uses: u32,
    /// The permitted application, or any application when absent.
    pub allowed_app_id: Option<Hash256>,
}

impl PreAuthorizedKeyRequest {
    fn sig_hash(&self, public_key: &PublicKey) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        "indexd/preauthorized-key/create/v1"
            .to_string()
            .encode(&mut state)
            .unwrap();
        public_key.encode(&mut state).unwrap();
        self.connect_key.encode(&mut state).unwrap();
        self.expiration.encode(&mut state).unwrap();
        u64::from(self.total_uses).encode(&mut state).unwrap();
        self.allowed_app_id.encode(&mut state).unwrap();
        state.finalize().into()
    }
}

/// A signed request to create a pre-authorized key in indexd.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreAuthorizedKeyRequest {
    /// The pre-authorized public key.
    pub public_key: PublicKey,
    /// The signature over the creation request.
    pub signature: Signature,

    /// The connect key used to authorize connections.
    pub connect_key: String,
    /// When the authorization expires.
    pub expiration: DateTime<Utc>,
    /// The maximum number of authorized connections.
    pub total_uses: u32,
    /// The permitted application, or any application when absent.
    #[serde(rename = "allowedAppID", skip_serializing_if = "Option::is_none")]
    pub allowed_app_id: Option<Hash256>,
}

/// A private key used to authorize application connections.
#[derive(Clone)]
pub struct PreAuthorizedKey(pub(crate) PrivateKey);

impl Default for PreAuthorizedKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PreAuthorizedKey {
    /// Generates a random pre-authorized key.
    pub fn new() -> Self {
        Self::import(rand::random())
    }

    /// Imports a pre-authorized key from a seed exported using [Self::export].
    pub fn import(buf: [u8; 32]) -> Self {
        PreAuthorizedKey(PrivateKey::from_seed(&buf))
    }

    /// Exports the key as a 32-byte seed for [Self::import].
    ///
    /// # Security
    /// This exported key is very sensitive and should be stored securely. Anyone with access
    /// to this key can connect apps as if they were the user. It is not recommended to store it
    /// longer than necessary.
    pub fn export(&self) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.0.as_ref()[..32]);
        arr
    }

    /// Signs a message using the pre-authorized key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Signs a creation request for submission to an indexer.
    pub fn sign_request(&self, req: PreAuthorizedKeyRequest) -> SignedPreAuthorizedKeyRequest {
        let public_key = self.public_key();
        let signature = self.sign(req.sig_hash(&public_key).as_ref());
        SignedPreAuthorizedKeyRequest {
            public_key,
            signature,
            connect_key: req.connect_key,
            expiration: req.expiration,
            total_uses: req.total_uses,
            allowed_app_id: req.allowed_app_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sia_core::hash_256;

    #[sia_core_derive::cross_target_test]
    fn test_generated_key_export_import() {
        let key = PreAuthorizedKey::new();
        let imported = PreAuthorizedKey::import(key.export());
        assert_eq!(imported.public_key(), key.public_key());
    }

    #[sia_core_derive::cross_target_test]
    fn test_creation_request_matches_indexd() {
        let key = PreAuthorizedKey::import([2; 32]);
        for (
            connect_key,
            seconds,
            nanos,
            expiration_json,
            allowed_app_id,
            expected_hash,
            expected_signature,
        ) in [
            (
                "connect-key",
                183,
                123_456_789,
                "1970-01-01T00:03:03.123456789Z",
                Some(Hash256::new([3; 32])),
                hash_256!("21123c55a2b0c73e1b21ab69d702c4c7a40c135b34aad82058a4e4e657e42b77"),
                "2ad300805a861694b3d88cc169300a49aa4f4ae55ed6fb287e97c488ee6682b8134fc9d65927e165673b5b7d98015efaccd2d9d18512f559732b34c300a7ad01",
            ),
            (
                "connect-key",
                183,
                123_456_789,
                "1970-01-01T00:03:03.123456789Z",
                None,
                hash_256!("44b6f44a076a87c78d0139ca8d9e2fd6ed9d2e3f1ad1cc4fad9a679b24babd3b"),
                "59a5c5c7c86695d234f8b3b8c018959fd1d22a158c6405be2fad9bb9195ab7a13970ffc9edd5c40a606468fead8e9e24e3877d2abbad92322c6df0ff8d800d0a",
            ),
            (
                "connect-key",
                183,
                123_456_789,
                "1970-01-01T00:03:03.123456789Z",
                Some(Hash256::new([0; 32])),
                hash_256!("65746658253ee3a79ec086f51b074f2aba0dccf6c5a684382ad8301870b20b46"),
                "bb13d0f5e6d6f5e752f610152195658ddaaaa281376c7816bf3820a6cf832165193a195cebcdbb8aa469484449cca2d92d5550269800cac24235b4176fb40901",
            ),
            (
                "connect-🔑-é",
                -1,
                500_000_000,
                "1969-12-31T23:59:59.500Z",
                Some(Hash256::new([3; 32])),
                hash_256!("e5cddeb3526d842a2d4c58f27e5aa6e589dfa5b4eda2b1e01a35593ddc322ff4"),
                "bccab3b043a53103b44266479e2d5c02529ac012c73a3224ae098678001d3299a9d5198bd96b1ee762f0f620654123ec8b5009ce20bd683eb80ad0da8d8e2809",
            ),
        ] {
            let expiration = DateTime::from_timestamp(seconds, nanos).unwrap();
            let req = PreAuthorizedKeyRequest {
                connect_key: connect_key.to_string(),
                expiration,
                total_uses: u32::MAX,
                allowed_app_id,
            };
            assert_eq!(req.sig_hash(&key.public_key()), expected_hash);

            let signed = key.sign_request(req);
            let mut expected = serde_json::json!({
                "publicKey": "ed25519:8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
                "signature": expected_signature,
                "connectKey": connect_key,
                "expiration": expiration_json,
                "totalUses": u32::MAX,
            });
            if let Some(id) = allowed_app_id {
                expected["allowedAppID"] = hex::encode(id).into();
            }
            assert_eq!(serde_json::to_value(&signed).unwrap(), expected);
        }
    }
}
