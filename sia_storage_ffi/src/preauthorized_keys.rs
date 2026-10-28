use std::time::SystemTime;

use sia_core::signing::Signature;
use sia_storage::Hash256;
use sia_storage::preauthorized_keys::{
    PreAuthorizedKey as StoragePreAuthorizedKey,
    PreAuthorizedKeyRequest as StoragePreAuthorizedKeyRequest,
};
use thiserror::Error;

/// An unsigned request to create a pre-authorized key in indexd.
#[derive(uniffi::Record)]
pub struct PreAuthorizedKeyRequest {
    pub connect_key: String,
    pub expiration: SystemTime,
    pub total_uses: u32,
    #[uniffi(default = None)]
    pub allowed_app_id: Option<String>,
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum PreAuthorizedKeyError {
    #[error("pre-authorized key seeds must be 32 bytes")]
    InvalidLength,

    #[error("signatures must be 64 bytes")]
    SignatureLength,

    #[error("invalid app ID: {0}")]
    InvalidAppId(String),

    #[error("invalid timestamp")]
    InvalidTimestamp,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// A key used to authorize application connections without interactive approval.
#[derive(uniffi::Object)]
pub struct PreAuthorizedKey(pub(crate) StoragePreAuthorizedKey);

impl Default for PreAuthorizedKey {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl PreAuthorizedKey {
    /// Generates a random pre-authorized key.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(StoragePreAuthorizedKey::new())
    }

    /// Imports a pre-authorized key from its 32-byte seed.
    #[uniffi::constructor]
    pub fn import(seed: Vec<u8>) -> Result<Self, PreAuthorizedKeyError> {
        let seed = seed
            .try_into()
            .map_err(|_| PreAuthorizedKeyError::InvalidLength)?;
        Ok(Self(StoragePreAuthorizedKey::import(seed)))
    }

    /// Exports the secret 32-byte seed for storage and later import.
    pub fn export(&self) -> Vec<u8> {
        self.0.export().to_vec()
    }

    /// Returns the public key as an ed25519-prefixed string.
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Signs a message with this key.
    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        self.0.sign(&message).as_ref().to_vec()
    }

    /// Verifies a message signature using this key's public key.
    pub fn verify_signature(
        &self,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, PreAuthorizedKeyError> {
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| PreAuthorizedKeyError::SignatureLength)?;
        Ok(self
            .0
            .public_key()
            .verify(&message, &Signature::from(signature)))
    }

    /// Returns the signed JSON body for creating a pre-authorized key in indexd.
    pub fn sign_request(
        &self,
        request: PreAuthorizedKeyRequest,
    ) -> Result<String, PreAuthorizedKeyError> {
        let PreAuthorizedKeyRequest {
            connect_key,
            expiration,
            total_uses,
            allowed_app_id,
        } = request;
        let allowed_app_id = allowed_app_id
            .map(|id| id.parse::<Hash256>())
            .transpose()
            .map_err(|e| PreAuthorizedKeyError::InvalidAppId(e.to_string()))?;
        let nanos = match expiration.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos() as i128,
            Err(error) => -(error.duration().as_nanos() as i128),
        };
        let seconds = i64::try_from(nanos.div_euclid(1_000_000_000))
            .map_err(|_| PreAuthorizedKeyError::InvalidTimestamp)?;
        let expiration =
            sia_storage::DateTime::from_timestamp(seconds, nanos.rem_euclid(1_000_000_000) as u32)
                .ok_or(PreAuthorizedKeyError::InvalidTimestamp)?;
        let signed = self.0.sign_request(StoragePreAuthorizedKeyRequest {
            connect_key,
            expiration,
            total_uses,
            allowed_app_id,
        });
        Ok(serde_json::to_string(&signed)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn sign_request_converts_inputs() {
        let key = PreAuthorizedKey::import(vec![2; 32]).unwrap();
        let core_key = StoragePreAuthorizedKey::import([2; 32]);
        for (expiration, expected_expiration, allowed_app_id, expected_allowed_app_id) in [
            (
                SystemTime::UNIX_EPOCH + Duration::new(183, 123_456_789),
                sia_storage::DateTime::from_timestamp(183, 123_456_789).unwrap(),
                Some("03".repeat(32)),
                Some(Hash256::new([3; 32])),
            ),
            (
                SystemTime::UNIX_EPOCH - Duration::from_millis(500),
                sia_storage::DateTime::from_timestamp(-1, 500_000_000).unwrap(),
                None,
                None,
            ),
        ] {
            let actual: serde_json::Value = serde_json::from_str(
                &key.sign_request(PreAuthorizedKeyRequest {
                    connect_key: "connect-🔑-é".into(),
                    expiration,
                    total_uses: u32::MAX,
                    allowed_app_id,
                })
                .unwrap(),
            )
            .unwrap();
            let expected =
                serde_json::to_value(core_key.sign_request(StoragePreAuthorizedKeyRequest {
                    connect_key: "connect-🔑-é".into(),
                    expiration: expected_expiration,
                    total_uses: u32::MAX,
                    allowed_app_id: expected_allowed_app_id,
                }))
                .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn invalid_inputs() {
        for length in [31, 33] {
            assert!(matches!(
                PreAuthorizedKey::import(vec![0; length]),
                Err(PreAuthorizedKeyError::InvalidLength)
            ));
        }
        let key = PreAuthorizedKey::import(vec![2; 32]).unwrap();
        assert!(matches!(
            key.verify_signature(vec![], vec![0; 63]),
            Err(PreAuthorizedKeyError::SignatureLength)
        ));
        assert!(matches!(
            key.sign_request(PreAuthorizedKeyRequest {
                connect_key: "connect-key".into(),
                expiration: SystemTime::UNIX_EPOCH,
                total_uses: 1,
                allowed_app_id: Some("invalid".into()),
            }),
            Err(PreAuthorizedKeyError::InvalidAppId(_))
        ));
        assert!(matches!(
            key.sign_request(PreAuthorizedKeyRequest {
                connect_key: "connect-key".into(),
                expiration: SystemTime::UNIX_EPOCH + Duration::from_secs(9_000_000_000_000),
                total_uses: 1,
                allowed_app_id: None,
            }),
            Err(PreAuthorizedKeyError::InvalidTimestamp)
        ));
    }
}
