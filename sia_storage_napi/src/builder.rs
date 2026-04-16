use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use sia_core::signing::Signature;
use sia_storage::Hash256;

use crate::{AppMeta, Sdk};

/// An AppKey is used to sign requests to the indexer.
///
/// AppKeys can be registered with an indexer during
/// onboarding with a Builder. They are derived from
/// a BIP-39 recovery phrase, which can be generated
/// using `generateRecoveryPhrase`.
///
/// It must be stored securely by the application and
/// never shared publicly.
#[napi]
pub struct AppKey(pub(crate) sia_storage::AppKey);

#[napi]
impl AppKey {
    /// Imports an AppKey from the provided byte array.
    #[napi(constructor)]
    pub fn new(key: Buffer) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::from_reason("app keys must be 32 bytes"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key);
        Ok(AppKey(sia_storage::AppKey::import(seed)))
    }

    /// Exports the AppKey as a 32-byte buffer.
    #[napi]
    pub fn export(&self) -> Buffer {
        Buffer::from(self.0.export().to_vec())
    }

    /// Signs a message using the AppKey.
    #[napi]
    pub fn sign(&self, message: Buffer) -> Buffer {
        let signature = self.0.sign(&message);
        Buffer::from(signature.as_ref().to_vec())
    }

    /// Returns the public key corresponding to the AppKey.
    #[napi]
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Verifies a signature for a given message using the AppKey.
    #[napi]
    pub fn verify_signature(&self, message: Buffer, signature: Buffer) -> Result<bool> {
        if signature.len() != 64 {
            return Err(Error::from_reason("signatures must be 64 bytes"));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature);
        Ok(self
            .0
            .public_key()
            .verify(&message, &Signature::from(sig_bytes)))
    }
}

/// Generates a new BIP-39 12-word recovery phrase.
#[napi]
pub fn generate_recovery_phrase() -> String {
    sia_storage::generate_recovery_phrase()
}

/// Validates a BIP-39 recovery phrase.
#[napi]
pub fn validate_recovery_phrase(phrase: String) -> Result<()> {
    sia_storage::validate_recovery_phrase(&phrase).map_err(|e| Error::from_reason(e.to_string()))
}

enum BuilderState {
    Disconnected(sia_storage::Builder<sia_storage::DisconnectedState>),
    RequestingApproval(sia_storage::Builder<sia_storage::RequestingApprovalState>),
    Approved(sia_storage::Builder<sia_storage::ApprovedState>),
    Finalized,
}

#[napi]
pub struct Builder {
    state: Arc<Mutex<Option<BuilderState>>>,
}

impl Builder {
    async fn with_state_transition<F, Fut, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(BuilderState) -> Fut,
        Fut: Future<Output = Result<(BuilderState, R)>>,
    {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::from_reason("mutex poisoned"))?
            .take();
        match state {
            Some(state) => {
                let (next, result) = f(state).await?;
                *self
                    .state
                    .lock()
                    .map_err(|_| Error::from_reason("mutex poisoned"))? = Some(next);
                Ok(result)
            }
            _ => Err(Error::from_reason("invalid state")),
        }
    }
}

#[napi]
impl Builder {
    /// Creates a new SDK builder with the provided indexer URL.
    #[napi(constructor)]
    pub fn new(indexer_url: String, app_meta: AppMeta) -> Result<Self> {
        if app_meta.id.len() != 32 {
            return Err(Error::from_reason("app ID must be 32 bytes"));
        }
        let app_id = Hash256::from(<[u8; 32]>::try_from(app_meta.id.as_ref()).unwrap());
        let app_meta = sia_storage::AppMetadata {
            id: app_id,
            name: Box::leak(app_meta.name.into_boxed_str()),
            description: Box::leak(app_meta.description.into_boxed_str()),
            service_url: Box::leak(app_meta.service_url.into_boxed_str()),
            logo_url: app_meta
                .logo_url
                .map(|s| Box::leak(s.into_boxed_str()) as &'static str),
            callback_url: app_meta
                .callback_url
                .map(|s| Box::leak(s.into_boxed_str()) as &'static str),
        };
        let builder = sia_storage::Builder::new(indexer_url, app_meta)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Builder {
            state: Arc::new(Mutex::new(Some(BuilderState::Disconnected(builder)))),
        })
    }

    /// Attempts to connect using the provided app key.
    /// Returns the SDK if the app key is valid, otherwise returns null.
    #[napi]
    pub async fn connected(&self, app_key: &AppKey) -> Result<Option<Sdk>> {
        let ak = app_key.0.clone();
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::Disconnected(builder) => {
                    match builder
                        .connected(&ak)
                        .await
                        .map_err(|e| Error::from_reason(e.to_string()))?
                    {
                        Some(sdk) => Ok((BuilderState::Finalized, Some(Sdk { inner: sdk }))),
                        None => Ok((BuilderState::Disconnected(builder), None)),
                    }
                }
                _ => Err(Error::from_reason("invalid state")),
            }
        })
        .await
    }

    /// Requests connection approval for the application.
    #[napi]
    pub async fn request_connection(&self) -> Result<()> {
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::Disconnected(builder) => {
                    let builder = builder
                        .request_connection()
                        .await
                        .map_err(|e| Error::from_reason(e.to_string()))?;
                    Ok((BuilderState::RequestingApproval(builder), ()))
                }
                _ => Err(Error::from_reason("invalid state")),
            }
        })
        .await
    }

    /// Returns the response URL for the connection request.
    #[napi]
    pub fn response_url(&self) -> Result<String> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::from_reason("mutex poisoned"))?;
        match state.as_ref() {
            Some(BuilderState::RequestingApproval(builder)) => {
                Ok(builder.response_url().to_owned())
            }
            _ => Err(Error::from_reason("invalid state")),
        }
    }

    /// Waits for the connection request to be approved.
    #[napi]
    pub async fn wait_for_approval(&self) -> Result<()> {
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::RequestingApproval(builder) => {
                    let builder = builder
                        .wait_for_approval()
                        .await
                        .map_err(|e| Error::from_reason(e.to_string()))?;
                    Ok((BuilderState::Approved(builder), ()))
                }
                _ => Err(Error::from_reason("invalid state")),
            }
        })
        .await
    }

    /// Registers the application with the indexer using the provided mnemonic.
    #[napi]
    pub async fn register(&self, mnemonic: String) -> Result<Sdk> {
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::Approved(builder) => {
                    let sdk = builder
                        .register(&mnemonic)
                        .await
                        .map_err(|e| Error::from_reason(e.to_string()))?;
                    Ok((BuilderState::Finalized, Sdk { inner: sdk }))
                }
                _ => Err(Error::from_reason("invalid state")),
            }
        })
        .await
    }
}
