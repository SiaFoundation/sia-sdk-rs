use base64::engine::general_purpose::URL_SAFE;
use base64::prelude::*;

use crate::encryption::EncryptionKey;
use crate::hosts::Host;
use blake2::Digest;
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde_with::base64::Base64;
use serde_with::{DefaultOnNull, serde_as};
use sia_core::blake2::Blake2b256;

use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::object_encryption::DecryptError;
use crate::slabs::{Sector, SlabVersion};
use crate::{
    Account, AppMetadata, HostQuery, Object, ObjectsCursor, PinnedSlab, SealedObject, Slab,
};
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::Hash256;

pub(crate) use reqwest::{IntoUrl, Url};

mod http;

#[cfg(any(test, feature = "mock"))]
pub(crate) mod mock;

const QUERY_PARAM_VALID_UNTIL: &str = "sv";
const QUERY_PARAM_CREDENTIAL: &str = "sc";
const QUERY_PARAM_SIGNATURE: &str = "ss";

const SHARE_URL_SCHEME: &str = "sia";

const ERROR_OBJECT_UNPINNED_SLAB: &str = "object contains unpinned slab";

#[cfg(not(test))]
const SHARE_URL_FETCH_SCHEME: &str = "https";
#[cfg(test)]
const SHARE_URL_FETCH_SCHEME: &str = "http";

/// Errors that can occur when communicating with the indexer API.
#[derive(Debug, Error)]
pub enum Error {
    /// The indexer returned an error response.
    #[error("indexd responded with an error: {0}")]
    Api(String),

    /// An invalid HTTP header value was constructed.
    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),

    /// An HTTP request error.
    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// A JSON serialization or deserialization error.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A URL could not be parsed.
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// The user rejected the connection request during the approval flow.
    #[error("user rejected connection request")]
    UserRejected,

    /// A response from the indexer had an unexpected format.
    #[error("format error: {0}")]
    Format(String),

    /// An error occurred during decryption.
    #[error("decryption error: {0}")]
    Decryption(#[from] DecryptError),

    /// A custom error.
    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, Error)]
pub enum PinObjectError {
    #[error("client error: {0}")]
    Client(#[from] Error),

    #[error("object contains unpinned slab")]
    UnpinnedSlab,
}

impl Error {
    /// Returns whether repeating the request may succeed. HTTP status codes are
    /// currently flattened into [`Error::Api`], so API responses must be
    /// treated as retryable alongside transport errors.
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(self, Self::Api(_) | Self::Reqwest(_))
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthConnectStatusResponse {
    approved: bool,
    user_secret: Option<Hash256>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterAppResponse {
    #[serde(rename = "responseURL")]
    pub response_url: String,
    #[serde(rename = "statusURL")]
    pub status_url: String,
    #[serde(rename = "registerURL")]
    pub register_url: String,
    pub expiration: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SlabPinParams {
    pub version: SlabVersion,
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

/// Maximum number of slabs to send in a single [`Client::pin_slabs`] request.
pub(crate) const SLAB_PIN_BATCH_SIZE: usize = 50;

impl From<&Slab> for SlabPinParams {
    fn from(slab: &Slab) -> Self {
        SlabPinParams {
            version: slab.version,
            encryption_key: slab.encryption_key.clone(),
            min_shards: slab.min_shards,
            sectors: slab.sectors.clone(),
        }
    }
}

/// An SealedObjectEvent represents an object and whether it was deleted or not.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealedObjectEvent {
    #[serde(rename = "key")]
    pub id: Hash256,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
    pub object: Option<SealedObject>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharedObjectResponse {
    pub slabs: Vec<Slab>,
    #[serde_as(as = "Option<Base64>")]
    pub encrypted_metadata: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterAppRequest {
    pub app_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectSlab {
    id: Hash256,
    offset: u32,
    length: u32,
}

#[serde_as]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PinObjectRequest {
    id: Hash256,
    #[serde_as(as = "Base64")]
    encrypted_data_key: Vec<u8>,
    slabs: Vec<ObjectSlab>,
    data_signature: Signature,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "DefaultOnNull<Base64>")]
    encrypted_metadata_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "DefaultOnNull<Base64>")]
    encrypted_metadata: Vec<u8>,
    metadata_signature: Signature,
}

impl From<&SealedObject> for PinObjectRequest {
    fn from(obj: &SealedObject) -> Self {
        PinObjectRequest {
            id: obj.id(),
            encrypted_data_key: obj.encrypted_data_key.clone(),
            slabs: obj
                .slabs
                .iter()
                .map(|s| ObjectSlab {
                    id: s.digest(),
                    offset: s.offset,
                    length: s.length,
                })
                .collect(),
            data_signature: obj.data_signature.clone(),
            encrypted_metadata_key: obj.encrypted_metadata_key.clone(),
            encrypted_metadata: obj.encrypted_metadata.clone(),
            metadata_signature: obj.metadata_signature.clone(),
        }
    }
}

/// The indexer API client. The `mock` feature adds an in-memory backend
/// alongside the HTTP one rather than replacing it, so a single build can
/// drive both.
#[derive(Clone)]
pub(crate) enum Client {
    Http(http::Client),
    #[cfg(any(test, feature = "mock"))]
    Mock(mock::Client),
}

impl Client {
    /// Creates a client that talks to a real indexer over HTTP.
    pub(crate) fn new<U: IntoUrl>(base_url: U) -> Result<Self, Error> {
        Ok(Self::Http(http::Client::new(base_url)?))
    }

    /// Creates a client backed by the in-memory mock indexer. Use
    /// [`Client::Mock`] directly when the test needs to keep the
    /// [`mock::Client`] handle to inspect what was pinned.
    #[cfg(test)]
    pub(crate) fn mock() -> Self {
        Self::Mock(mock::Client::new())
    }

    /// Checks if the application is authenticated with the indexer. It returns
    /// true if authenticated, false if not, and an error if the request fails.
    pub(crate) async fn check_app_authenticated(
        &self,
        app_key: &PrivateKey,
    ) -> Result<bool, Error> {
        match self {
            Self::Http(c) => c.check_app_authenticated(app_key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.check_app_authenticated(app_key).await,
        }
    }

    /// Requests an application connection to the indexer.
    pub(crate) async fn request_app_connection(
        &self,
        ephemeral_key: &PrivateKey,
        opts: &AppMetadata,
    ) -> Result<RegisterAppResponse, Error> {
        match self {
            Self::Http(c) => c.request_app_connection(ephemeral_key, opts).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.request_app_connection(ephemeral_key, opts).await,
        }
    }

    /// Checks if an auth request has been approved.
    ///
    /// If approved, it returns the user secret used
    /// to derive the application key.
    ///
    /// If the auth request is still pending, it returns None.
    pub(crate) async fn check_request_status(
        &self,
        ephemeral_key: &PrivateKey,
        status_url: Url,
    ) -> Result<Option<Hash256>, Error> {
        match self {
            Self::Http(c) => c.check_request_status(ephemeral_key, status_url).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.check_request_status(ephemeral_key, status_url).await,
        }
    }

    /// Registers the application key with the indexer.
    pub(crate) async fn register_app(
        &self,
        signing_key: &PrivateKey,
        app_key: &PrivateKey,
        register_url: Url,
    ) -> Result<(), Error> {
        match self {
            Self::Http(c) => c.register_app(signing_key, app_key, register_url).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.register_app(signing_key, app_key, register_url).await,
        }
    }

    /// Returns all usable hosts.
    ///
    /// # Arguments
    /// * `query` - Parameters to control the hosts listing.
    pub(crate) async fn hosts(
        &self,
        app_key: &PrivateKey,
        query: HostQuery,
    ) -> Result<Vec<Host>, Error> {
        match self {
            Self::Http(c) => c.hosts(app_key, query).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.hosts(app_key, query).await,
        }
    }

    /// Retrieves an object from the indexer by its key.
    pub(crate) async fn object(
        &self,
        app_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<SealedObject, Error> {
        match self {
            Self::Http(c) => c.object(app_key, key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.object(app_key, key).await,
        }
    }

    /// Fetches a list of objects from the indexer. Can be paginated using the
    /// cursor and limit arguments.
    pub(crate) async fn objects(
        &self,
        app_key: &PrivateKey,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<SealedObjectEvent>, Error> {
        match self {
            Self::Http(c) => c.objects(app_key, cursor, limit).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.objects(app_key, cursor, limit).await,
        }
    }

    /// Pins an object to the indexer. If an object with the same ID already
    /// exists for the account, it is overwritten.
    pub(crate) async fn pin_object(
        &self,
        app_key: &PrivateKey,
        object: &SealedObject,
    ) -> Result<(), PinObjectError> {
        match self {
            Self::Http(c) => c.pin_object(app_key, object).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.pin_object(app_key, object).await,
        }
    }

    /// Deletes an object from the indexer by its key.
    pub(crate) async fn delete_object(
        &self,
        app_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<(), Error> {
        match self {
            Self::Http(c) => c.delete_object(app_key, key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.delete_object(app_key, key).await,
        }
    }

    /// Retrieves a slab from the indexer by its ID.
    pub(crate) async fn slab(
        &self,
        app_key: &PrivateKey,
        slab_id: &Hash256,
    ) -> Result<PinnedSlab, Error> {
        match self {
            Self::Http(c) => c.slab(app_key, slab_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.slab(app_key, slab_id).await,
        }
    }

    /// Pins slabs to the indexer.
    pub(crate) async fn pin_slabs(
        &self,
        app_key: &PrivateKey,
        slabs: &[SlabPinParams],
    ) -> Result<Vec<Hash256>, Error> {
        match self {
            Self::Http(c) => c.pin_slabs(app_key, slabs).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.pin_slabs(app_key, slabs).await,
        }
    }

    /// Unpins slabs not used by any object on the account.
    pub(crate) async fn prune_slabs(&self, app_key: &PrivateKey) -> Result<(), Error> {
        match self {
            Self::Http(c) => c.prune_slabs(app_key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.prune_slabs(app_key).await,
        }
    }

    /// Account returns the current account.
    pub(crate) async fn account(&self, app_key: &PrivateKey) -> Result<Account, Error> {
        match self {
            Self::Http(c) => c.account(app_key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.account(app_key).await,
        }
    }

    /// Creates a signed url that can be shared with others
    /// to give read access to a single object. An expired
    /// link does not necessarily remove access to an object.
    ///
    /// # Arguments
    /// - `object` the object to create the link for
    /// - `valid_until` the time the link expires
    pub(crate) fn shared_object_url(
        &self,
        app_key: &PrivateKey,
        object: &Object,
        valid_until: DateTime<Utc>,
    ) -> Result<Url, Error> {
        match self {
            Self::Http(c) => c.shared_object_url(app_key, object, valid_until),
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_object_url(app_key, object, valid_until),
        }
    }

    /// Retrieves the object metadata using a pre-signed url
    ///
    /// # Arguments
    /// `share_url` a pre-signed url for the App objects API
    ///
    /// # Returns
    /// The metadata needed to download the data
    pub(crate) async fn shared_object(&self, share_url: Url) -> Result<Object, Error> {
        match self {
            Self::Http(c) => c.shared_object(share_url).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_object(share_url).await,
        }
    }
}

fn request_hash(
    url: &Url,
    method: Method,
    body: Option<&[u8]>,
    valid_until: DateTime<Utc>,
) -> Hash256 {
    let host_port = url
        .port()
        .map_or(url.host_str().unwrap_or("localhost").to_string(), |port| {
            format!("{}:{}", url.host_str().unwrap_or("localhost"), port)
        });
    let mut state = Blake2b256::new();
    state.update(method.as_str().as_bytes());
    state.update(host_port.as_bytes());
    state.update(url.path().as_bytes());
    state.update(valid_until.timestamp().to_le_bytes());
    if let Some(body) = body {
        state.update(body);
    }
    state.finalize().into()
}

fn sign(
    app_key: &PrivateKey,
    url: &Url,
    method: Method,
    body: Option<&[u8]>,
    valid_until: DateTime<Utc>,
) -> [(&'static str, String); 3] {
    let hash = request_hash(url, method, body, valid_until);
    let public_key = app_key.public_key();
    let signature = app_key.sign(hash.as_ref());
    [
        (QUERY_PARAM_VALID_UNTIL, valid_until.timestamp().to_string()),
        (QUERY_PARAM_CREDENTIAL, URL_SAFE.encode(public_key)),
        (QUERY_PARAM_SIGNATURE, URL_SAFE.encode(signature.as_ref())),
    ]
}

fn register_app_sig_hash(request_id: &str, ephemeral_key: &PublicKey) -> Hash256 {
    const KEY_DOMAIN: &[u8] = b"registerAppKey";

    Blake2b256::default()
        .chain_update(KEY_DOMAIN)
        .chain_update(ephemeral_key)
        .chain_update(request_id.as_bytes())
        .finalize()
        .into()
}

/// Pure computation tests (signing, hashing, encoding) — run on both native and WASM.
#[cfg(test)]
mod cross_target_test {
    use base64::engine::general_purpose::URL_SAFE;
    use base64::prelude::*;
    use sia_core::{hash_256, public_key, signature};

    use crate::slabs::SlabVersion::V0;
    use crate::slabs::object_id;
    use crate::time::Duration;

    use super::*;

    #[sia_core_derive::cross_target_test]
    fn test_register_app_sig_hash_golden() {
        const REQUEST_ID: &str = "ebddc9385dace70f9a97cebce34134ac";
        const EPHEMERAL_KEY: PublicKey =
            public_key!("ed25519:9f5fb0b962f29497b3993e12c7a7880fbaf0cf52bad3620af0280895fdea8ece");
        const EXPECTED_SIG_HASH: Hash256 =
            hash_256!("3017354ace367561d4c568263463c17d3c16030c637734e12e9418be1f2f8e65");

        assert_eq!(
            register_app_sig_hash(REQUEST_ID, &EPHEMERAL_KEY),
            EXPECTED_SIG_HASH,
            "expected sig hash did not match"
        );
    }

    /// Ensures that our base64 url encoding is compatible with our Go implementation.
    #[sia_core_derive::cross_target_test]
    fn test_base64_url() {
        const DATA: &[u8] = b"hello, world!";
        const ENCODED_DATA: &str = "aGVsbG8sIHdvcmxkIQ==";

        let encoded = URL_SAFE.encode(DATA);
        assert_eq!(encoded, ENCODED_DATA);
    }

    #[sia_core_derive::cross_target_test]
    fn test_request_hash() {
        let method = Method::POST;
        let url = Url::parse("https://foo.bar/foo").unwrap();
        let valid_until = DateTime::from_timestamp_secs(123).unwrap();
        let body = b"hello world!";
        let hash = request_hash(&url, method, Some(body), valid_until);
        assert_eq!(
            hash,
            hash_256!("a9f0bda1b97b7d44ae6369ac830851a115311bb59aa2d848beda6ae95d10ad18")
        )
    }

    #[sia_core_derive::cross_target_test]
    fn test_sign() {
        let app_key = PrivateKey::from_seed(&[0u8; 32]);

        // with body
        let params = sign(
            &app_key,
            &"https://foo.bar/baz.jpg".parse().unwrap(),
            Method::POST,
            Some("{}".as_bytes()),
            DateTime::from_timestamp_secs(123).unwrap() + Duration::from_secs(60),
        );
        assert_eq!(params[0], (QUERY_PARAM_VALID_UNTIL, "183".to_string()));
        assert_eq!(
            params[1],
            (
                QUERY_PARAM_CREDENTIAL,
                URL_SAFE.encode(public_key!(
                    "ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
                )),
            )
        );
        assert_eq!(
            params[2],
            (
                QUERY_PARAM_SIGNATURE,
                URL_SAFE.encode(signature!("458283fd707c9d170d5e1814944f35893c53c9445fd46c74a6b285bf3029bf404c9af509ea271d811726bd20d8c7d8fe4b9efdc4bebb445f18059eca886ece03").as_ref()),
            )
        );

        // without body
        let params = sign(
            &app_key,
            &"https://foo.bar/baz.jpg".parse().unwrap(),
            Method::GET,
            None,
            DateTime::from_timestamp_secs(123).unwrap() + Duration::from_secs(60),
        );
        assert_eq!(params[0], (QUERY_PARAM_VALID_UNTIL, "183".to_string()));
        assert_eq!(
            params[1],
            (
                QUERY_PARAM_CREDENTIAL,
                URL_SAFE.encode(
                    public_key!(
                        "ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
                    )
                    .as_ref()
                )
            )
        );
        assert_eq!(
            params[2],
            (
                QUERY_PARAM_SIGNATURE,
                URL_SAFE.encode(signature!("7411fc80f920cb098690498133be075cd43bf6385fc8348fe1946e29d909891680d45651dfb0a6fd9f7196a971816c21441852362680f2fe4cb935de8f90380b").as_ref()),
            )
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_shared_object_id() {
        let obj = SharedObjectResponse {
            slabs: vec![Slab {
                version: V0,
                encryption_key: [0u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([1u8; 32]),
                    host_key: PublicKey::new([2u8; 32]),
                }],
                offset: 10,
                length: 100,
            }],
            encrypted_metadata: None,
        };

        assert_eq!(
            object_id(&obj.slabs).to_string(),
            "1b13d5dd22605af0573cae7fe9242c1ee83727c29798308b2b170864677b46d0"
        );
    }
}
