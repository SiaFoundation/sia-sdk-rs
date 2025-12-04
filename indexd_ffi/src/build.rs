use std::sync::{Arc, Mutex};

use indexd::app_client::RegisterAppRequest;
use indexd::{self, AppKey as _, Url};
use sia::seed::{self, Seed};
use sia::signing::PrivateKey;
use thiserror::Error;

use crate::{AppMeta, SDK, spawn, tls};

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AppKeyError {
    #[error(transparent)]
    AppKey(#[from] indexd::AppKeyError),
}

/// An AppKey is used to sign requests to the indexer.
#[derive(uniffi::Object)]
pub struct AppKey(PrivateKey);

impl AppKey {
    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.0
    }
}

#[uniffi::export]
impl AppKey {
    /// Creates a new AppKey from a recovery phrase and a unique app ID.
    /// The app ID should be a unique 32-byte value. The value is not secret,
    /// but it should be random and unique to the app.
    #[uniffi::constructor]
    pub fn new(key_string: String) -> Result<Self, AppKeyError> {
        let app_key = PrivateKey::import(&key_string)?;
        Ok(Self(app_key))
    }

    /// Exports the AppKey as a string. This string can be used to
    /// recreate the AppKey using [AppKey::new].
    ///
    /// It should be stored securely by the application in lieue of the
    /// recovery phrase.
    pub fn export(&self) -> String {
        self.0.export()
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
        let state = { self.state.lock().unwrap().take() };
        match state {
            Some(state) => {
                let (next, result) = spawn(async move { f(state).await }).await.unwrap()?;
                *self.state.lock().unwrap() = Some(next);
                Ok(result)
            }
            _ => Err(BuilderError::InvalidState),
        }
    }

    fn with_state<F, R>(&self, f: F) -> Result<R, BuilderError>
    where
        F: FnOnce(&BuilderState) -> Result<R, BuilderError>,
    {
        let state = self.state.lock().unwrap();
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
                            service_url: Url::parse(&meta.service_url).expect("oops"),
                            logo_url: meta.logo_url.map(|s| Url::parse(&s).expect("oops")),
                            callback_url: meta.callback_url.map(|s| Url::parse(&s).expect("oops")),
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
            BuilderState::RequestingApproval(builder) => Ok(builder.response_url()),
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

    /// Derives the application key using the provided mnemonic. The
    /// app key can be used to complete the registration process.
    /// It should be stored securely by the application for future use.
    ///
    /// # Arguments
    /// * `mnemonic` - The BIP-39 mnemonic phrase used for key derivation. Can be generated using [generate_recovery_phrase].
    pub fn app_key(&self, mnemonic: String) -> Result<AppKey, BuilderError> {
        self.with_state(|state| match state {
            BuilderState::Approved(builder) => {
                let app_key = builder.app_key(&mnemonic)?;
                Ok(AppKey(app_key))
            }
            _ => Err(BuilderError::InvalidState),
        })
    }

    /// Registers the application with the indexer using the provided app key.
    /// Once registered, returns an [SDK] instance that can be used to interact
    /// with the indexer.
    ///
    /// # Arguments
    /// * `app_key` - The application key used for registration. Can be derived using [Builder::app_key].
    pub async fn register(&self, app_key: Arc<AppKey>) -> Result<SDK, BuilderError> {
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
                    let sdk = builder.register(app_key.0.clone(), rustls_config).await?;
                    Ok((BuilderState::Finalized, SDK { inner: sdk }))
                }
                _ => Err(BuilderError::InvalidState),
            }
        })
        .await
    }
}
