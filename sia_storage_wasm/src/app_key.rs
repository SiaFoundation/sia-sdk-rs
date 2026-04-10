use sia_core::signing::Signature;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;

/// An application key used for authentication with the indexer.
///
/// AppKeys are derived from a BIP-39 recovery phrase during registration.
/// They can be exported as a 32-byte seed and re-imported for future
/// connections. The key must be stored securely — anyone with access
/// can authenticate as the user.
#[wasm_bindgen]
pub struct AppKey(pub(crate) sia_storage::AppKey);

#[wasm_bindgen]
impl AppKey {
    /// Imports an AppKey from a 32-byte seed (Uint8Array).
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8]) -> Result<AppKey, JsValue> {
        if seed.len() != 32 {
            return Err(JsValue::from_str("app key seed must be 32 bytes"));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(seed);
        Ok(AppKey(sia_storage::AppKey::import(buf)))
    }

    /// Exports the AppKey as a 32-byte seed (Uint8Array).
    pub fn export(&self) -> Vec<u8> {
        self.0.export().to_vec()
    }

    /// Imports an AppKey from a hex-encoded string (64 hex chars = 32-byte seed,
    /// or 128 hex chars = 64-byte ed25519 keypair).
    #[wasm_bindgen(js_name = "fromHex")]
    pub fn from_hex(hex_str: &str) -> Result<AppKey, JsValue> {
        let bytes = hex::decode(hex_str).map_err(to_js_err)?;
        match bytes.len() {
            32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&bytes);
                Ok(AppKey(sia_storage::AppKey::import(buf)))
            }
            64 => {
                // 64-byte ed25519 keypair — seed is first 32 bytes
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&bytes[..32]);
                Ok(AppKey(sia_storage::AppKey::import(buf)))
            }
            _ => Err(JsValue::from_str(
                "hex string must be 64 chars (32-byte seed) or 128 chars (64-byte keypair)",
            )),
        }
    }

    /// Exports the AppKey as a hex-encoded string (64 hex chars / 32-byte seed).
    #[wasm_bindgen(js_name = "toHex")]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.export())
    }

    /// Returns the ed25519 public key as a string (e.g. "ed25519:abc123...").
    #[wasm_bindgen(js_name = "publicKey")]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Signs a message and returns the 64-byte ed25519 signature (Uint8Array).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).as_ref().to_vec()
    }

    /// Verifies a signature for a given message.
    /// Returns true if the signature is valid.
    #[wasm_bindgen(js_name = "verifySignature")]
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
        if signature.len() != 64 {
            return Err(JsValue::from_str("signature must be 64 bytes"));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        Ok(self
            .0
            .public_key()
            .verify(message, &Signature::from(sig_bytes)))
    }
}
