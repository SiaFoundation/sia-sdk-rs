use chrono::DateTime;
use sia_core::signing::Signature;
use sia_storage::preauthorized_keys::{
    PreAuthorizedKeyRequest as StoragePreAuthorizedKeyRequest,
    SignedPreAuthorizedKeyRequest as StorageSignedPreAuthorizedKeyRequest,
};
use tsify::Ts;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;

/// An unsigned request to create a pre-authorized key in indexd.
#[derive(serde::Deserialize, tsify::Tsify)]
#[serde(rename_all = "camelCase")]
pub struct PreAuthorizedKeyRequest {
    /// The connect key used to authorize connections.
    pub connect_key: String,
    /// When the authorization expires.
    #[serde(with = "serde_wasm_bindgen::preserve")]
    #[tsify(type = "Date")]
    pub expiration: js_sys::Date,
    /// The maximum number of authorized connections.
    pub total_uses: f64,
    /// The permitted application, or any application when absent.
    #[serde(rename = "allowedAppID")]
    #[tsify(optional, type = "string | null")]
    pub allowed_app_id: Option<String>,
}

/// A signed request to create a pre-authorized key in indexd.
#[derive(serde::Serialize, tsify::Tsify)]
#[serde(transparent)]
pub struct SignedPreAuthorizedKeyRequest(
    #[tsify(type = "{
    publicKey: string;
    signature: string;
    connectKey: string;
    expiration: string;
    totalUses: number;
    allowedAppID?: string;
}")]
    pub StorageSignedPreAuthorizedKeyRequest,
);

/// A key used to authorize application connections with indexd.
#[derive(Default)]
#[wasm_bindgen]
pub struct PreAuthorizedKey(pub(crate) sia_storage::preauthorized_keys::PreAuthorizedKey);

#[wasm_bindgen]
impl PreAuthorizedKey {
    /// Generates a new pre-authorized key.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(sia_storage::preauthorized_keys::PreAuthorizedKey::new())
    }

    /// Imports a pre-authorized key from a 32-byte seed.
    pub fn import(seed: &[u8]) -> Result<PreAuthorizedKey, JsError> {
        let seed = <[u8; 32]>::try_from(seed)
            .map_err(|_| JsError::new("pre-authorized key seed must be 32 bytes"))?;
        Ok(Self(
            sia_storage::preauthorized_keys::PreAuthorizedKey::import(seed),
        ))
    }

    /// Exports the key as a 32-byte seed.
    pub fn export(&self) -> Vec<u8> {
        self.0.export().to_vec()
    }

    /// Returns the Ed25519 public key as a string.
    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Signs a message and returns its 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).as_ref().to_vec()
    }

    /// Verifies a message signature using this key.
    #[wasm_bindgen(js_name = "verifySignature")]
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        let signature = <[u8; 64]>::try_from(signature)
            .map_err(|_| JsError::new("signature must be 64 bytes"))?;
        Ok(self
            .0
            .public_key()
            .verify(message, &Signature::from(signature)))
    }

    /// Returns a signed request for creating a pre-authorized key in indexd.
    #[wasm_bindgen(js_name = "signRequest")]
    pub fn sign_request(
        &self,
        request: Ts<PreAuthorizedKeyRequest>,
    ) -> Result<Ts<SignedPreAuthorizedKeyRequest>, JsError> {
        let PreAuthorizedKeyRequest {
            connect_key,
            expiration,
            total_uses,
            allowed_app_id,
        } = request.to_rust()?;
        let millis = expiration.get_time();
        if !millis.is_finite() {
            return Err(JsError::new("invalid expiration"));
        }
        let expiration = DateTime::from_timestamp_millis(millis as i64)
            .ok_or_else(|| JsError::new("invalid expiration"))?;
        if total_uses.fract() != 0.0 || !(0.0..=u32::MAX as f64).contains(&total_uses) {
            return Err(JsError::new(
                "total uses must be an unsigned 32-bit integer",
            ));
        }
        let allowed_app_id = allowed_app_id
            .map(|id| id.parse::<sia_storage::Hash256>())
            .transpose()
            .map_err(to_js_err)?;
        let request = self.0.sign_request(StoragePreAuthorizedKeyRequest {
            connect_key,
            expiration,
            total_uses: total_uses as u32,
            allowed_app_id,
        });
        Ok(Ts::from_rust(&SignedPreAuthorizedKeyRequest(request))?)
    }
}
