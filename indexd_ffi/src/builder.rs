use std::sync::{Arc, Mutex};

use indexd::app_client::RegisterAppRequest;
use indexd::{self, Url};
use sia::seed::{self, Seed};
use sia::signing::{PrivateKey, Signature};
use thiserror::Error;

use crate::{AppMeta, SDK, spawn, tls};

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AppKeyError {
    #[error("app keys must be 32 bytes")]
    InvalidLength,

    #[error("signatures must be 64 bytes")]
    SignatureLength,
}

/// An AppKey is used to sign requests to the indexer.
///
/// AppKeys can be registered with an indexer during
/// onboarding with a [Builder]. They are derived from
/// a BIP-32 recovery phrase, which can be generated
/// using [generate_recovery_phrase].
///
/// It must be stored securely by the application and
/// never shared publicly. If exposed, a user's data
/// is compromised.
///
/// Mishandling the app key will lead to data loss
/// and inability to access stored objects.

#[derive(uniffi::Object)]
pub struct AppKey(PrivateKey);

impl AppKey {
    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.0
    }
}

#[uniffi::export]
impl AppKey {
    /// Imports an AppKey from the provided byte array.
    ///
    /// # Arguments
    /// * `key` - A 32-byte array representing the app key.
    #[uniffi::constructor]
    pub fn new(key: Vec<u8>) -> Result<Self, AppKeyError> {
        if key.len() != 32 {
            return Err(AppKeyError::InvalidLength);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key);
        Ok(AppKey(PrivateKey::from_seed(&seed)))
    }

    /// Exports the AppKey. The app key can be re-imported later
    /// using [AppKey::new].
    ///
    /// AppKeys should be stored securely by the application in lieu of the
    /// recovery phrase.
    pub fn export(&self) -> Vec<u8> {
        self.0.as_ref()[..32].to_vec()
    }

    /// Signs a message using the AppKey.
    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        let signature = self.0.sign(&message);
        signature.as_ref().to_vec()
    }

    /// Returns the public key corresponding to the AppKey.
    ///
    /// This can be safely shared with others.
    pub fn public_key(&self) -> String {
        self.0.public_key().to_string()
    }

    /// Verifies a signature for a given message using the AppKey.
    pub fn verify_signature(
        &self,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, AppKeyError> {
        if signature.len() != 64 {
            return Err(AppKeyError::SignatureLength);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature);
        Ok(self
            .0
            .public_key()
            .verify(&message, &Signature::from(sig_bytes)))
    }
}

impl From<PrivateKey> for AppKey {
    fn from(pk: PrivateKey) -> Self {
        AppKey(pk)
    }
}

#[derive(uniffi::Error, Debug, Error)]
#[uniffi(flat_error)]
pub enum SeedError {
    #[error(transparent)]
    InvalidMnemonic(#[from] seed::SeedError),
}

/// Generates a new BIP-32 12-word recovery phrase.
#[uniffi::export]
pub fn generate_recovery_phrase() -> String {
    let seed: [u8; 16] = rand::random();
    Seed::from_seed(seed).to_string()
}

/// Validates a BIP-32 recovery phrase.
#[uniffi::export]
pub fn validate_recovery_phrase(phrase: &str) -> Result<(), SeedError> {
    Seed::new(phrase)?;
    Ok(())
}

enum BuilderState {
    Disconnected(indexd::Builder<indexd::DisconnectedState>),
    RequestingApproval(indexd::Builder<indexd::RequestingApprovalState>),
    Approved(indexd::Builder<indexd::ApprovedState>),
    Finalized,
}

#[derive(uniffi::Object)]
pub struct Builder {
    state: Arc<Mutex<Option<BuilderState>>>,
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum BuilderError {
    #[error(transparent)]
    Error(#[from] indexd::BuilderError),

    #[error("invalid state for this operation")]
    InvalidState,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("{0}")]
    Custom(String),
}

impl Builder {
    async fn with_state_transition<F, Fut, R>(&self, f: F) -> Result<R, BuilderError>
    where
        R: Send + 'static,
        F: FnOnce(BuilderState) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(BuilderState, R), BuilderError>> + Send + 'static,
    {
        let state = {
            self.state
                .lock()
                .map_err(|_| BuilderError::Custom("mutex poisoned".into()))?
                .take()
        };
        match state {
            Some(state) => {
                let (next, result) = spawn(async move { f(state).await }).await??;
                *self
                    .state
                    .lock()
                    .map_err(|_| BuilderError::Custom("mutex poisoned".into()))? = Some(next);
                Ok(result)
            }
            _ => Err(BuilderError::InvalidState),
        }
    }

    fn with_state<F, R>(&self, f: F) -> Result<R, BuilderError>
    where
        F: FnOnce(&BuilderState) -> Result<R, BuilderError>,
    {
        let state = self
            .state
            .lock()
            .map_err(|_| BuilderError::Custom("mutex poisoned".into()))?;
        match state.as_ref() {
            Some(state) => f(state),
            None => Err(BuilderError::InvalidState),
        }
    }
}

#[uniffi::export]
impl Builder {
    /// Creates a new SDK builder with the provided indexer URL.
    ///
    /// After creating the builder, call [Builder::connected] to attempt
    /// to connect using an existing app key, or [Builder::request_connection]
    /// to request a new connection.
    #[uniffi::constructor]
    pub fn new(indexer_url: String) -> Result<Self, BuilderError> {
        let builder = indexd::Builder::new(indexer_url)?;
        Ok(Builder {
            state: Arc::new(Mutex::new(Some(BuilderState::Disconnected(builder)))),
        })
    }

    /// Attempts to connect using the provided app key and TLS configuration.
    /// If the app key is valid, returns Some([SDK]), otherwise returns None.
    ///
    /// If you receive None, call [Builder::request_connection] to request a new connection.
    ///
    /// # Arguments
    /// * `app_key` - The application key used for authentication.
    pub async fn connected(&self, app_key: Arc<AppKey>) -> Result<Option<Arc<SDK>>, BuilderError> {
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::Disconnected(builder) => {
                    // install crypto provider
                    if rustls::crypto::CryptoProvider::get_default().is_none() {
                        rustls::crypto::ring::default_provider()
                            .install_default()
                            .map_err(|e| BuilderError::Crypto(format!("{:?}", e)))?;
                    }
                    let rustls_config = tls::tls_config();

                    match builder.connected(&app_key.0, rustls_config).await? {
                        Some(sdk) => {
                            Ok((BuilderState::Finalized, Some(Arc::new(SDK { inner: sdk }))))
                        }
                        None => Ok((BuilderState::Disconnected(builder), None)),
                    }
                }
                _ => Err(BuilderError::InvalidState),
            }
        })
        .await
    }

    /// Requests a new connection for the application.
    ///
    /// # Arguments
    /// * `app` - Details of the application requesting connection.
    pub async fn request_connection(&self, meta: AppMeta) -> Result<Self, BuilderError> {
        self.with_state_transition(|state| async move {
            if meta.id.len() != 32 {
                return Err(BuilderError::Custom("app ID must be 32 bytes".to_string()));
            }
            let mut app_id = [0u8; 32];
            app_id.copy_from_slice(&meta.id);
            match state {
                BuilderState::Disconnected(builder) => {
                    let builder = builder
                        .request_connection(&RegisterAppRequest {
                            app_id: app_id.into(),
                            name: meta.name,
                            description: meta.description,
                            service_url: Url::parse(&meta.service_url).map_err(|e| {
                                BuilderError::Custom(format!("invalid service url: {e}"))
                            })?,
                            logo_url: meta
                                .logo_url
                                .map(|s| {
                                    Url::parse(&s).map_err(|e| {
                                        BuilderError::Custom(format!("invalid logo url: {e}"))
                                    })
                                })
                                .transpose()?,
                            callback_url: meta
                                .callback_url
                                .map(|s| {
                                    Url::parse(&s).map_err(|e| {
                                        BuilderError::Custom(format!("invalid callback url: {e}"))
                                    })
                                })
                                .transpose()?,
                        })
                        .await?;
                    Ok((BuilderState::RequestingApproval(builder), ()))
                }
                _ => Err(BuilderError::InvalidState),
            }
        })
        .await?;

        Ok(Builder {
            state: self.state.clone(),
        })
    }

    /// Retrieves the response URL for the connection request.
    /// This URL can be used to approve the connection request.
    /// It should be displayed to the user.
    pub fn response_url(&self) -> Result<String, BuilderError> {
        self.with_state(|state| match state {
            BuilderState::RequestingApproval(builder) => Ok(builder.response_url().to_owned()),
            _ => Err(BuilderError::InvalidState),
        })
    }

    /// Waits for the connection request to be approved.
    /// Once approved, the app can be registered and used to create an
    /// SDK instance.
    pub async fn wait_for_approval(&self) -> Result<Self, BuilderError> {
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::RequestingApproval(builder) => {
                    let builder = builder.wait_for_approval().await?;
                    // transition to approved state
                    Ok((BuilderState::Approved(builder), ()))
                }
                _ => Err(BuilderError::InvalidState),
            }
        })
        .await?;
        Ok(Builder {
            state: self.state.clone(),
        })
    }

    /// Registers the application with the indexer using the provided mnemonic.
    /// Once registered, returns an [SDK] instance that can be used to interact
    /// with the indexer.
    ///
    /// # Arguments
    /// * `mnemonic` - The user's mnemonic phrase used to derive the application key.
    pub async fn register(&self, mnemonic: String) -> Result<Arc<SDK>, BuilderError> {
        self.with_state_transition(|state| async move {
            match state {
                BuilderState::Approved(builder) => {
                    // install crypto provider
                    if rustls::crypto::CryptoProvider::get_default().is_none() {
                        rustls::crypto::ring::default_provider()
                            .install_default()
                            .map_err(|e| BuilderError::Crypto(format!("{:?}", e)))?;
                    }
                    let rustls_config = tls::tls_config();
                    let sdk = builder.register(&mnemonic, rustls_config).await?;
                    Ok((BuilderState::Finalized, Arc::new(SDK { inner: sdk })))
                }
                _ => Err(BuilderError::InvalidState),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_phrase() {
        let phrase = generate_recovery_phrase();
        assert!(validate_recovery_phrase(&phrase).is_ok());
    }

    #[test]
    fn test_validate_recovery_phrase_invalid() {
        let invalid_phrase = "invalid recovery phrase";
        assert!(validate_recovery_phrase(invalid_phrase).is_err());
    }

    #[test]
    fn test_app_key_export() {
        let seed: [u8; 32] = rand::random();
        let app_key = AppKey::new(seed.to_vec()).unwrap();
        let exported = app_key.export();
        assert_eq!(exported, seed.to_vec());
    }
}