use chrono::{DateTime, SecondsFormat};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use sia_core::signing::Signature;
use sia_storage::preauthorized_keys::PreAuthorizedKeyRequest as StoragePreAuthorizedKeyRequest;

/// An unsigned request to create a pre-authorized key in indexd.
#[napi(object, object_to_js = false)]
pub struct PreAuthorizedKeyRequest<'env> {
    pub connect_key: String,
    pub expiration: Date<'env>,
    pub total_uses: f64,
    #[napi(js_name = "allowedAppID", ts_type = "string | null")]
    pub allowed_app_id: Option<Either<String, Null>>,
}

/// A signed request to create a pre-authorized key in indexd.
#[napi(object)]
pub struct SignedPreAuthorizedKeyRequest {
    pub public_key: String,
    pub signature: String,
    pub connect_key: String,
    pub expiration: String,
    pub total_uses: u32,
    #[napi(js_name = "allowedAppID")]
    pub allowed_app_id: Option<String>,
}

/// A key used to authorize application connections with indexd.
#[derive(Default)]
#[napi]
pub struct PreAuthorizedKey(pub(crate) sia_storage::preauthorized_keys::PreAuthorizedKey);

#[napi]
impl PreAuthorizedKey {
    /// Generates a new pre-authorized key.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self(sia_storage::preauthorized_keys::PreAuthorizedKey::new())
    }

    /// Imports a pre-authorized key from a 32-byte seed.
    #[napi(factory)]
    pub fn import(seed: Buffer) -> Result<Self> {
        let seed = <[u8; 32]>::try_from(seed.as_ref())
            .map_err(|_| Error::from_reason("pre-authorized key seed must be 32 bytes"))?;
        Ok(Self(
            sia_storage::preauthorized_keys::PreAuthorizedKey::import(seed),
        ))
    }

    /// Exports the key as a 32-byte seed.
    #[napi]
    pub fn export(&self) -> Buffer {
        self.0.export().to_vec().into()
    }

    /// Returns the Ed25519 public key as a string.
    #[napi]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Signs a message and returns its 64-byte signature.
    #[napi]
    pub fn sign(&self, message: Buffer) -> Buffer {
        self.0.sign(&message).as_ref().to_vec().into()
    }

    /// Verifies a message signature using this key.
    #[napi]
    pub fn verify_signature(&self, message: Buffer, signature: Buffer) -> Result<bool> {
        let signature = <[u8; 64]>::try_from(signature.as_ref())
            .map_err(|_| Error::from_reason("signatures must be 64 bytes"))?;
        Ok(self
            .0
            .public_key()
            .verify(&message, &Signature::from(signature)))
    }

    /// Returns the signed request for creating a pre-authorized key in indexd.
    #[napi]
    pub fn sign_request(
        &self,
        request: PreAuthorizedKeyRequest<'_>,
    ) -> Result<SignedPreAuthorizedKeyRequest> {
        if !(0.0..=u32::MAX as f64).contains(&request.total_uses)
            || request.total_uses.fract() != 0.0
        {
            return Err(Error::from_reason("invalid total uses"));
        }
        let millis = request.expiration.value_of()?;
        if !millis.is_finite() {
            return Err(Error::from_reason("invalid expiration"));
        }
        let expiration = DateTime::from_timestamp_millis(millis as i64)
            .ok_or_else(|| Error::from_reason("invalid expiration"))?;
        let allowed_app_id = request
            .allowed_app_id
            .and_then(Option::<String>::from)
            .map(|id| {
                id.parse::<sia_storage::Hash256>()
                    .map_err(|e| Error::from_reason(e.to_string()))
            })
            .transpose()?;
        let request = self.0.sign_request(StoragePreAuthorizedKeyRequest {
            connect_key: request.connect_key,
            expiration,
            total_uses: request.total_uses as u32,
            allowed_app_id,
        });
        Ok(SignedPreAuthorizedKeyRequest {
            public_key: request.public_key.to_string(),
            signature: request.signature.to_string(),
            connect_key: request.connect_key,
            expiration: request
                .expiration
                .to_rfc3339_opts(SecondsFormat::AutoSi, true),
            total_uses: request.total_uses,
            allowed_app_id: request.allowed_app_id.map(|id| id.to_string()),
        })
    }
}
