use crate::time::sleep;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rand::random;
use reqwest::{IntoUrl, StatusCode};
use sia_core::seed::{self, Seed};
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;
use thiserror::Error;
use url::Url;

use crate::app_client::{self, Client};
use crate::object_encryption::hkdf;
use crate::time::Duration;
use crate::{AppID, AppKey, AppMetadata, Sdk};

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
    reconnecting: bool,
}

/// A builder for creating an SDK instance.
pub struct Builder<S> {
    ephemeral_key: PrivateKey,
    state: S,
    client: Client,
    app_meta: AppMetadata,
}

/// Errors that can occur during the SDK building process.
#[derive(Error, Debug)]
pub enum BuilderError {
    /// A URL could not be parsed.
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    /// An error from the indexer API client.
    #[error("client error: {0}")]
    Client(#[from] app_client::Error),

    /// A transport-level connection error.
    #[error("transport error: {0}")]
    Transport(String),

    /// The recovery phrase is invalid.
    #[error("mnemonic error: {0}")]
    Mnemonic(#[from] seed::SeedError),

    /// The connection approval request expired before the user approved it.
    #[error("request expired")]
    RequestExpired,

    /// The recovery phrase does not derive the app key of the account that
    /// is already connected to this application.
    #[error("recovery phrase does not match the existing account")]
    WrongRecoveryPhrase,

    /// The indexer rejected the pre-authorized connection request. The key is
    /// usually invalid, expired, exhausted, or restricted to a different
    /// application; the indexer's response is included.
    #[error("pre-authorized key rejected: {0}")]
    PreAuthorizedKeyRejected(String),
}

impl Builder<DisconnectedState> {
    /// Creates a new SDK builder with the provided indexer URL.
    ///
    /// After creating the builder, call [Builder::connected] to attempt
    /// to connect using an existing app key, or [Builder::request_connection]
    /// to request a new connection.
    ///
    /// # Example
    /// ```rust
    /// use sia_storage::{AppMetadata, Builder, app_id};
    ///
    /// const APP_META: AppMetadata = AppMetadata {
    ///     id: app_id!("a9f0bda1b97b7d44ae6369ac830851a115311bb59aa2d848beda6ae95d10ad18"),
    ///     name: "My App",
    ///     description: "My App Description",
    ///     service_url: "https://myapp.com",
    ///     logo_url: Some("https://myapp.com/logo.png"),
    ///     callback_url: Some("https://myapp.com/callback"),
    /// };
    ///
    /// let builder = Builder::new("https://sia.storage", APP_META).expect("failed to create builder");
    /// ```
    pub fn new<U: IntoUrl>(indexer_url: U, app_meta: AppMetadata) -> Result<Self, BuilderError> {
        let client = Client::new(indexer_url)?;
        Ok(Self {
            ephemeral_key: PrivateKey::from_seed(&random::<[u8; 32]>()),
            state: DisconnectedState,
            client,
            app_meta,
        })
    }

    /// Attempts to connect using the provided app key.
    /// If the app key is valid, returns Some([Sdk]), otherwise returns None.
    ///
    /// If you receive None, call [Builder::request_connection] to request a new connection.
    ///
    /// # Arguments
    /// * `app_key` - The application key used for authentication.
    pub async fn connected(&self, app_key: &AppKey) -> Result<Option<Sdk>, BuilderError> {
        let connected = self.client.check_app_authenticated(&app_key.0).await?;
        if !connected {
            return Ok(None);
        }
        let sdk = Sdk::new(self.client.clone(), Arc::new(app_key.clone())).await?;
        Ok(Some(sdk))
    }

    /// Connects using a pre-authorized key, bypassing the interactive approval
    /// flow, and returns a ready [Sdk].
    ///
    /// The pre-authorized key must have been registered with the indexer and
    /// still be valid. Because the indexer approves the request immediately,
    /// this performs the entire connect, approve, and register flow in one call.
    /// The application key is derived from `mnemonic` exactly as in the
    /// interactive flow, so a later [Builder::connected] call reconnects to the
    /// same account.
    ///
    /// # Arguments
    /// * `pre_authorized_key` - The pre-authorized key used to approve the connection.
    /// * `mnemonic` - The user's mnemonic phrase used to derive the application key.
    pub async fn connect_pre_authorized(
        self,
        pre_authorized_key: &PrivateKey,
        mnemonic: &str,
    ) -> Result<Sdk, BuilderError> {
        // fail before the request consumes a use of the pre-authorized key
        Seed::new(mnemonic)?;

        let resp = self
            .client
            .request_app_connection_pre_authorized(
                &self.ephemeral_key,
                &self.app_meta,
                pre_authorized_key,
            )
            .await
            .map_err(|e| match e {
                app_client::Error::Api(StatusCode::UNAUTHORIZED, msg) => {
                    BuilderError::PreAuthorizedKeyRejected(msg)
                }
                e => e.into(),
            })?;

        // The indexer approves a valid pre-authorized request synchronously, so
        // the user secret is available on the first status check.
        let status = self
            .client
            .check_request_status(&self.ephemeral_key, Url::parse(&resp.status_url)?)
            .await?
            .ok_or_else(|| {
                BuilderError::PreAuthorizedKeyRejected(
                    "the indexer did not approve the request".to_string(),
                )
            })?;

        let private_key = derive_app_key(mnemonic, &self.app_meta.id, &status.user_secret)?;
        if status.reconnecting && !self.client.check_app_authenticated(&private_key).await? {
            return Err(BuilderError::WrongRecoveryPhrase);
        }
        self.client
            .register_app(
                &self.ephemeral_key,
                &private_key,
                Url::parse(&resp.register_url)?,
            )
            .await?;
        Sdk::new(self.client, Arc::new(AppKey(private_key))).await
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

            if let Some(status) = self
                .client
                .check_request_status(&self.ephemeral_key, self.state.status_url.clone())
                .await?
            {
                return Ok(Builder {
                    ephemeral_key: self.ephemeral_key,
                    state: ApprovedState {
                        register_url: self.state.register_url.clone(),
                        user_secret: status.user_secret,
                        reconnecting: status.reconnecting,
                    },
                    app_meta: self.app_meta,
                    client: self.client,
                });
            }
            sleep(Duration::from_secs(5)).await;
        }
    }
}

impl Builder<ApprovedState> {
    /// Returns whether the connect key the user approved with already has an
    /// account for this application.
    ///
    /// A returning user must supply the same recovery phrase to
    /// [Builder::register] to regain access to their data.
    pub fn reconnecting(&self) -> bool {
        self.state.reconnecting
    }

    /// Completes the registration process and returns an SDK instance.
    ///
    /// When reconnecting, the derived app key is verified against the indexer
    /// before registering. If it does not belong to the existing account,
    /// this fails with [BuilderError::WrongRecoveryPhrase] instead of
    /// registering a new account.
    ///
    /// # Arguments
    /// * `mnemonic` - The user's mnemonic phrase used to derive the application key.
    ///
    /// # Errors
    /// Returns [BuilderError] if the registration fails or the SDK cannot be created.
    pub async fn register(self, mnemonic: &str) -> Result<Sdk, BuilderError> {
        let private_key = derive_app_key(mnemonic, &self.app_meta.id, &self.state.user_secret)?;
        if self.state.reconnecting && !self.client.check_app_authenticated(&private_key).await? {
            return Err(BuilderError::WrongRecoveryPhrase);
        }
        self.client
            .register_app(
                &self.ephemeral_key,
                &private_key,
                self.state.register_url.clone(),
            )
            .await?;
        Sdk::new(self.client, Arc::new(AppKey(private_key))).await
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
    hkdf(&key, app_id.as_ref(), KEY_DOMAIN, &mut okm);
    Ok(PrivateKey::from_seed(&okm))
}

#[cfg(test)]
mod test {
    use crate::app_id;

    use super::*;
    use sia_core::hash_256;
    use sia_core::types::Hash256;

    #[sia_core_derive::cross_target_test]
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

/// Integration tests requiring httptest, a native TCP mock server. Native only.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_tests {
    use super::*;
    use crate::app_id;
    use httptest::http::Response;
    use httptest::matchers::request;
    use httptest::{Expectation, Server};

    const MNEMONIC: &str = "glare own entire dish exact open theme family harsh room scrap rose";
    const APP_META: AppMetadata = AppMetadata {
        id: app_id!("0e90d697f5045a6593f1c43ebf79a369e2bc72cc5c7b6282f3b5aeb0de6e4005"),
        name: "test-app",
        description: "A test application",
        service_url: "https://test-app.com",
        logo_url: None,
        callback_url: None,
    };

    /// Starts a server that approves a connection request for a returning user.
    fn reconnecting_approval_server() -> Server {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("POST", "/auth/connect")).respond_with(
                Response::builder()
                    .status(200)
                    .body(format!(
                        r#"{{"responseURL":"http://example.com/auth/connect/req","statusURL":"{}","registerURL":"{}","expiration":"2030-01-01T00:00:00Z"}}"#,
                        server.url("/auth/connect/req/status"),
                        server.url("/auth/connect/req/register"),
                    ))
                    .unwrap(),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/connect/req/status"))
                .respond_with(
                    Response::builder()
                        .status(200)
                        .body(r#"{"approved":true,"reconnecting":true,"userSecret":"cf02d945fe4bfe614d823dc13c19aa8501699e656d0f7915490c3056d5c97dc6"}"#)
                        .unwrap(),
                ),
        );
        server
    }

    #[tokio::test]
    async fn test_register_reconnecting() {
        // correct recovery phrase, the app key passes the check and registration proceeds
        let server = reconnecting_approval_server();
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check"))
                .respond_with(Response::builder().status(204).body("").unwrap()),
        );
        server.expect(
            Expectation::matching(request::method_path("POST", "/auth/connect/req/register"))
                .respond_with(Response::builder().status(200).body("").unwrap()),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/hosts"))
                .respond_with(Response::builder().status(200).body("[]").unwrap()),
        );

        let builder = Builder::new(server.url("/").to_string(), APP_META).unwrap();
        let builder = builder.request_connection().await.unwrap();
        let builder = builder.wait_for_approval().await.unwrap();
        assert!(builder.reconnecting());
        builder.register(MNEMONIC).await.unwrap();

        // wrong recovery phrase, the app key fails the check and registration is refused
        let server = reconnecting_approval_server();
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check"))
                .respond_with(Response::builder().status(401).body("").unwrap()),
        );
        server.expect(
            Expectation::matching(request::method_path("POST", "/auth/connect/req/register"))
                .times(0)
                .respond_with(Response::builder().status(200).body("").unwrap()),
        );

        let builder = Builder::new(server.url("/").to_string(), APP_META).unwrap();
        let builder = builder.request_connection().await.unwrap();
        let builder = builder.wait_for_approval().await.unwrap();
        let Err(err) = builder.register(MNEMONIC).await else {
            panic!("expected register to fail");
        };
        assert!(matches!(err, BuilderError::WrongRecoveryPhrase));
    }
}
