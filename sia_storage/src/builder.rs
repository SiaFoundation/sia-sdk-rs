use std::sync::Arc;
use std::time::Duration;

use crate::rhp4::siamux;
use chrono::{DateTime, Utc};
use log::debug;
use rand::random;
use reqwest::IntoUrl;
use sia_core::seed::{self, Seed};
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;
use thiserror::Error;
use url::Url;

use crate::app_client::{self, Client};
use crate::object_encryption::derive;
use crate::{AppID, AppMetadata, SDK};

/// The initial state of the SDK builder, before connecting to the indexd service.
pub struct DisconnectedState;

/// The state of the SDK builder after requesting approval for the application.
pub struct RequestingApprovalState {
    response_url: Url,
    register_url: Url,
    status_url: Url,
    expiration: DateTime<Utc>,
}

/// The state of the SDK builder after the application has been approved.
pub struct ApprovedState {
    register_url: Url,
    user_secret: Hash256,
}

/// A builder for creating an SDK instance.
pub struct Builder<S> {
    ephemeral_key: PrivateKey,
    state: S,
    client: Client,
    app_meta: AppMetadata,
    tls_config: rustls::ClientConfig,
}

/// Errors that can occur during the SDK building process.
#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("client error: {0}")]
    Client(#[from] app_client::Error),

    #[error("transport error: {0}")]
    Transport(#[from] siamux::ConnectError),

    #[error("mnemonic error: {0}")]
    Mnemonic(#[from] seed::SeedError),

    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("request expired")]
    RequestExpired,
}

impl Builder<DisconnectedState> {
    /// Creates a new SDK builder with the provided indexer URL using the
    /// platform TLS verifier.
    ///
    /// After creating the builder, call [Builder::connected] to attempt
    /// to connect using an existing app key, or [Builder::request_connection]
    /// to request a new connection.
    ///
    /// # Example
    /// ```rust
    /// use sia_storage::{AppMetadata, Builder, app_id};
    ///
    /// const app_meta: AppMetadata = AppMetadata {
    ///     id: app_id!("a9f0bda1b97b7d44ae6369ac830851a115311bb59aa2d848beda6ae95d10ad18"),
    ///     name: "My App",
    ///     description: "My App Description",
    ///     service_url: "https://myapp.com",
    ///     logo_url: Some("https://myapp.com/logo.png"),
    ///     callback_url: Some("https://myapp.com/callback"),
    /// };
    ///
    /// let builder = Builder::new("https://app.sia.storage", app_meta).expect("failed to create builder");
    /// ```
    #[cfg(feature = "platform-verifier")]
    pub fn new<U: IntoUrl>(indexer_url: U, app_meta: AppMetadata) -> Result<Self, BuilderError> {
        use rustls_platform_verifier::ConfigVerifierExt;
        let tls_config = rustls::ClientConfig::with_platform_verifier()?;
        Self::with_tls_config(indexer_url, app_meta, tls_config)
    }

    /// Creates a new SDK builder with the provided indexer URL and TLS
    /// configuration.
    ///
    /// [Builder::new] should be preferred unless you need
    /// a custom TLS configuration.
    ///
    /// After creating the builder, call [Builder::connected] to attempt
    /// to connect using an existing app key, or [Builder::request_connection]
    /// to request a new connection.
    pub fn with_tls_config<U: IntoUrl>(
        indexer_url: U,
        app_meta: AppMetadata,
        tls_config: rustls::ClientConfig,
    ) -> Result<Self, BuilderError> {
        debug!(
            "Creating SDK builder for indexer at {}",
            indexer_url.as_str()
        );
        let client = Client::new(indexer_url)?;
        Ok(Self {
            ephemeral_key: PrivateKey::from_seed(&random::<[u8; 32]>()),
            state: DisconnectedState,
            client,
            app_meta,
            tls_config,
        })
    }

    /// Attempts to connect using the provided app key.
    /// If the app key is valid, returns Some([SDK]), otherwise returns None.
    ///
    /// If you receive None, call [Builder::request_connection] to request a new connection.
    ///
    /// # Arguments
    /// * `app_key` - The application key used for authentication.
    pub async fn connected(&self, app_key: &PrivateKey) -> Result<Option<SDK>, BuilderError> {
        let connected = self.client.check_app_authenticated(app_key).await?;
        if !connected {
            return Ok(None);
        }
        let sdk = SDK::new(self.client.clone(), Arc::new(app_key.clone())).await?;
        Ok(Some(sdk))
    }

    /// Requests a new connection for the application.
    ///
    /// # Arguments
    /// * `app` - Details of the application requesting connection.
    pub async fn request_connection(
        self,
    ) -> Result<Builder<RequestingApprovalState>, BuilderError> {
        let resp = self
            .client
            .request_app_connection(&self.ephemeral_key, &self.app_meta)
            .await?;
        Ok(Builder {
            ephemeral_key: self.ephemeral_key,
            app_meta: self.app_meta,
            state: RequestingApprovalState {
                response_url: Url::parse(&resp.response_url)?,
                register_url: Url::parse(&resp.register_url)?,
                status_url: Url::parse(&resp.status_url)?,
                expiration: resp.expiration,
            },
            client: self.client,
            tls_config: self.tls_config,
        })
    }
}

impl Builder<RequestingApprovalState> {
    /// Returns the response URL for the registration process. This
    /// should be displayed to the user so they can authorize the
    /// application.
    pub fn response_url(&self) -> &str {
        self.state.response_url.as_str()
    }

    /// Waits for the application registration to be approved. This
    /// polls the status URL until the registration is approved or
    /// rejected. This can take several minutes depending on user action.
    ///
    /// [Builder::response_url] should be displayed to the user
    /// before calling this method.
    pub async fn wait_for_approval(self) -> Result<Builder<ApprovedState>, BuilderError> {
        loop {
            if Utc::now() >= self.state.expiration {
                return Err(BuilderError::RequestExpired);
            }

            if let Some(user_secret) = self
                .client
                .check_request_status(&self.ephemeral_key, self.state.status_url.clone())
                .await?
            {
                return Ok(Builder {
                    ephemeral_key: self.ephemeral_key,
                    state: ApprovedState {
                        register_url: self.state.register_url.clone(),
                        user_secret,
                    },
                    app_meta: self.app_meta,
                    client: self.client,
                    tls_config: self.tls_config,
                });
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

impl Builder<ApprovedState> {
    /// Completes the registration process and returns an SDK instance.
    ///
    /// # Arguments
    /// * `mnemonic` - The user's mnemonic phrase used to derive the application key.
    ///
    /// # Errors
    /// Returns [BuilderError] if the registration fails or the SDK cannot be created.
    pub async fn register(self, mnemonic: &str) -> Result<SDK, BuilderError> {
        let app_key = derive_app_key(mnemonic, &self.app_meta.id, &self.state.user_secret)?;
        self.client
            .register_app(
                &self.ephemeral_key,
                &app_key,
                self.state.register_url.clone(),
            )
            .await?;
        SDK::new(self.client, Arc::new(app_key)).await
    }
}

/// A helper function to derive an application key from a
/// mnemonic, app ID, and shared secret.
///
/// It is exposed to be able to test the app key derivation logic.
fn derive_app_key(
    mnemonic: &str,
    app_id: &AppID,
    shared_secret: &Hash256,
) -> Result<PrivateKey, BuilderError> {
    const KEY_DOMAIN: &[u8] = b"indexd app key derivation";
    let seed = Seed::new(mnemonic)?;
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(seed.entropy());
    key[32..].copy_from_slice(shared_secret.as_ref());
    let mut okm = [0u8; 32];
    derive(&key, app_id.as_ref(), KEY_DOMAIN, &mut okm);
    Ok(PrivateKey::from_seed(&okm))
}

#[cfg(test)]
mod test {
    use crate::app_id;

    use super::*;
    use sia_core::hash_256;
    use sia_core::types::Hash256;

    #[test]
    fn test_app_key_derivation_golden() {
        const MNEMONIC: &str =
            "glare own entire dish exact open theme family harsh room scrap rose";
        const APP_ID: AppID =
            app_id!("0e90d697f5045a6593f1c43ebf79a369e2bc72cc5c7b6282f3b5aeb0de6e4005");
        const SHARED_SECRET: Hash256 =
            hash_256!("cf02d945fe4bfe614d823dc13c19aa8501699e656d0f7915490c3056d5c97dc6");
        const EXPECTED_APP_KEY: &str =
            "b75061f34bb3aeab232b0671da2d0347c547343a0026bb5535c291d964fd09a1";

        let mut seed = [0u8; 32];
        hex::decode_to_slice(EXPECTED_APP_KEY, &mut seed).expect("decoding failed");
        let expected_app_key = PrivateKey::from_seed(&seed);

        let derived_app_key =
            derive_app_key(MNEMONIC, &APP_ID, &SHARED_SECRET).expect("derivation failed");
        assert_eq!(derived_app_key, expected_app_key);
    }
}
