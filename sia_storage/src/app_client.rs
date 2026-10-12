use base64::engine::general_purpose::URL_SAFE;
use base64::prelude::*;

use crate::encryption::EncryptionKey;
use crate::hosts::Host;
use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use reqwest::{Method, StatusCode};
use serde_with::base64::Base64;
use serde_with::{DefaultOnNull, serde_as};

use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::object_encryption::DecryptError;
use crate::sharing::{KeyRequest, Nonce, SharedObjectRequest};
use crate::slabs::{Base64OrBytes, SealedObjectSummary, Sector, SlabVersion};
use crate::{Account, AppMetadata, HostQuery, Object, ObjectsCursor, SealedObject, Slab};
use sia_core::rhp4::AccountToken;
use sia_core::signing::{PrivateKey, PublicKey, Signature};
use sia_core::types::Hash256;

pub(crate) use reqwest::{IntoUrl, Url};

mod http;

#[cfg(any(test, feature = "mock"))]
pub(crate) mod mock;

const QUERY_PARAM_VALID_UNTIL: &str = "sv";
pub(crate) const QUERY_PARAM_CREDENTIAL: &str = "sc";
const QUERY_PARAM_SIGNATURE: &str = "ss";

const SHARE_URL_SCHEME: &str = "sia";

const ERROR_OBJECT_UNPINNED_SLAB: &str = "object contains unpinned slab";
const ERROR_SLAB_UPLOAD_TOO_OLD: &str = "slab upload is too old";

#[cfg(not(test))]
const SHARE_URL_FETCH_SCHEME: &str = "https";
#[cfg(test)]
const SHARE_URL_FETCH_SCHEME: &str = "http";

/// Errors that can occur when communicating with the indexer API.
#[derive(Debug, Error)]
pub enum Error {
    /// The indexer returned an error response.
    #[error("indexd responded with an error: {0}: {1}")]
    Api(StatusCode, String),

    /// An invalid HTTP header value was constructed.
    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),

    /// An HTTP request error.
    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// A JSON serialization or deserialization error.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A CBOR deserialization error.
    #[error("cbor error: {0}")]
    Cbor(#[from] ciborium::de::Error<std::io::Error>),

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
    /// Returns whether the indexer rejected the slab as too old to pin, so it
    /// must be uploaded again.
    pub(crate) fn is_slab_upload_too_old(&self) -> bool {
        matches!(self, Self::Api(StatusCode::BAD_REQUEST, message) if message.contains(ERROR_SLAB_UPLOAD_TOO_OLD))
    }

    /// Returns whether repeating the request may succeed.
    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::Api(
                StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED,
                _,
            ) => false,
            Self::Api(..) | Self::Reqwest(_) | Self::Serde(_) | Self::Cbor(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthConnectStatusResponse {
    approved: bool,
    #[serde(default)]
    reconnecting: bool,
    user_secret: Option<Hash256>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct AuthApproval {
    pub user_secret: Hash256,
    pub reconnecting: bool,
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
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub expiration: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SlabPinParams {
    pub version: SlabVersion,
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<SectorPinParams>,
}

/// Parameters for pinning a sector as part of a slab pin request.
/// Fresh uploads include the write attempt's start time; re-pinning an existing
/// slab omits it. The upload time is not part of the pinned slab or its ID.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SectorPinParams {
    #[serde(flatten)]
    pub sector: Sector,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<DateTime<Utc>>,
}

/// Maximum number of slabs to send in a single [`Client::pin_slabs`] request.
pub(crate) const SLAB_PIN_BATCH_SIZE: usize = 50;

impl SlabPinParams {
    /// Returns the slab ID, excluding sector upload times.
    pub(crate) fn digest(&self) -> Hash256 {
        Slab::from(self).digest()
    }
}

/// Converts pin parameters to a slab with zero offset and length, since pin
/// requests do not include the slab's position within an object.
impl From<&SlabPinParams> for Slab {
    fn from(params: &SlabPinParams) -> Self {
        Self {
            version: params.version,
            encryption_key: params.encryption_key.clone(),
            min_shards: params.min_shards,
            sectors: params.sectors.iter().map(|s| s.sector.clone()).collect(),
            offset: 0,
            length: 0,
        }
    }
}

impl From<&Slab> for SlabPinParams {
    fn from(slab: &Slab) -> Self {
        SlabPinParams {
            version: slab.version,
            encryption_key: slab.encryption_key.clone(),
            min_shards: slab.min_shards,
            sectors: slab
                .sectors
                .iter()
                .cloned()
                .map(|sector| SectorPinParams {
                    sector,
                    uploaded_at: None,
                })
                .collect(),
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
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub updated_at: DateTime<Utc>,
    pub object: Option<SealedObject>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharedObjectResponse {
    #[serde_as(as = "DefaultOnNull")]
    pub slabs: Vec<Slab>,
    #[serde_as(as = "Option<Base64OrBytes>")]
    pub encrypted_metadata: Option<Vec<u8>>,
}

/// A host and the account token that pays it, as returned by `GET /shared/hosts`.
/// The token is signed by the owner's sharing account, so downloads are charged
/// to the owner rather than the recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedHost {
    #[serde(flatten)]
    pub host: Host,
    pub token: AccountToken,
}

/// What a recipient can see about the sharing key they hold: how many objects
/// it grants access to, how much space they use, and when the key expires. The
/// counts are a snapshot, not a live view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyStats {
    /// The number of objects the sharing key grants access to.
    pub object_count: u64,
    /// The total logical size of those objects, in bytes.
    pub object_size: u64,
    /// The size of those objects stored on the network, excluding redundancy.
    pub pinned_data: u64,
    /// The size of those objects stored on the network, including redundancy.
    pub pinned_size: u64,
    /// When the sharing key expires, if it expires at all.
    pub expires_at: Option<DateTime<Utc>>,
    /// When the sharing key was created.
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub created_at: DateTime<Utc>,
    /// When the sharing key was last updated.
    #[serde(with = "sia_core::types::null_as_zero_time")]
    pub updated_at: DateTime<Utc>,
}

/// A sharing key record from the indexer: the key's public half and nonce, the
/// account that owns it, its description, and its [`KeyStats`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyResponse {
    /// The public half of the sharing key.
    pub public_key: PublicKey,
    /// The nonce the key was derived from.
    pub nonce: Nonce,
    /// The account that owns the key.
    pub account: PublicKey,
    /// A human-readable description.
    pub description: String,
    /// How many objects the key grants access to and how much space they use.
    #[serde(flatten)]
    pub stats: KeyStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterAppRequest {
    pub app_key: PublicKey,
    pub signature: Signature,
}

/// The body of a pre-authorized `auth/connect` request.
#[derive(Serialize)]
struct AppConnectRequest<'a> {
    #[serde(flatten)]
    metadata: &'a AppMetadata,
    #[serde(rename = "preAuthorizedKey")]
    pre_authorized_key: PublicKey,
    #[serde(rename = "preAuthorizationSignature")]
    pre_authorization_signature: Signature,
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

/// Requests pages until one comes back short, which ends the listing.
///
/// Pages are the largest the indexer accepts, so today's network
/// of a few hundred hosts is one request. Each page waits for the one before
/// it, so a smaller page costs a round trip per hundred hosts.
async fn drain_pages<T, F, Fut>(page: F) -> Result<Vec<T>, Error>
where
    F: Fn(HostQuery) -> Fut,
    Fut: Future<Output = Result<Vec<T>, Error>>,
{
    const PAGE_SIZE: u64 = 500;
    let mut all = Vec::new();
    loop {
        let page = page(HostQuery {
            offset: Some(all.len() as u64),
            limit: Some(PAGE_SIZE),
            ..Default::default()
        })
        .await?;
        let done = (page.len() as u64) < PAGE_SIZE;
        all.extend(page);
        if done {
            return Ok(all);
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

    /// Requests an application connection using a pre-authorized key, bypassing
    /// the interactive approval flow.
    pub(crate) async fn request_app_connection_pre_authorized(
        &self,
        ephemeral_key: &PrivateKey,
        opts: &AppMetadata,
        pre_authorized_key: &PrivateKey,
    ) -> Result<RegisterAppResponse, Error> {
        match self {
            Self::Http(c) => {
                c.request_app_connection_pre_authorized(ephemeral_key, opts, pre_authorized_key)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => {
                c.request_app_connection_pre_authorized(ephemeral_key, opts, pre_authorized_key)
                    .await
            }
        }
    }

    /// Checks if an auth request has been approved. Returns None if the
    /// request is still pending.
    pub(crate) async fn check_request_status(
        &self,
        ephemeral_key: &PrivateKey,
        status_url: Url,
    ) -> Result<Option<AuthApproval>, Error> {
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

    /// Every host the indexer has for this app.
    pub(crate) async fn all_hosts(&self, app_key: &PrivateKey) -> Result<Vec<Host>, Error> {
        drain_pages(|query| self.hosts(app_key, query)).await
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
    pub(crate) async fn prune_slabs(
        &self,
        app_key: &PrivateKey,
        before: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        match self {
            Self::Http(c) => c.prune_slabs(app_key, before).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.prune_slabs(app_key, before).await,
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

    /// Fetches the sharing key's stats from the indexer.
    pub(crate) async fn shared_stats(&self, sharing_key: &PrivateKey) -> Result<KeyStats, Error> {
        match self {
            Self::Http(c) => c.shared_stats(sharing_key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_stats(sharing_key).await,
        }
    }

    /// Lists the objects the sharing key grants access to.
    pub(crate) async fn shared_objects(
        &self,
        sharing_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<SealedObject>, Error> {
        match self {
            Self::Http(c) => c.shared_objects(sharing_key, offset, limit).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_objects(sharing_key, offset, limit).await,
        }
    }

    /// Lists the objects the sharing key grants access to without their
    /// slabs.
    pub(crate) async fn shared_object_summaries(
        &self,
        sharing_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<SealedObjectSummary>, Error> {
        match self {
            Self::Http(c) => c.shared_object_summaries(sharing_key, offset, limit).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_object_summaries(sharing_key, offset, limit).await,
        }
    }

    /// Retrieves a single object the sharing key grants access to.
    pub(crate) async fn shared_object_by_id(
        &self,
        sharing_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<SealedObject, Error> {
        match self {
            Self::Http(c) => c.shared_object_by_id(sharing_key, key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_object_by_id(sharing_key, key).await,
        }
    }

    /// Lists usable hosts, each paired with an account token the recipient uses
    /// to pay for downloads from it.
    pub(crate) async fn shared_hosts(
        &self,
        sharing_key: &PrivateKey,
        query: HostQuery,
    ) -> Result<Vec<SharedHost>, Error> {
        match self {
            Self::Http(c) => c.shared_hosts(sharing_key, query).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.shared_hosts(sharing_key, query).await,
        }
    }

    /// Sharing key equivalent of [`Client::all_hosts`].
    pub(crate) async fn all_shared_hosts(
        &self,
        sharing_key: &PrivateKey,
    ) -> Result<Vec<SharedHost>, Error> {
        drain_pages(|query| self.shared_hosts(sharing_key, query)).await
    }

    /// Creates a sharing key for the account.
    pub(crate) async fn add_sharing_key(
        &self,
        app_key: &PrivateKey,
        req: &KeyRequest,
    ) -> Result<KeyResponse, Error> {
        match self {
            Self::Http(c) => c.add_sharing_key(app_key, req).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.add_sharing_key(app_key, req).await,
        }
    }

    /// Lists the account's sharing keys.
    pub(crate) async fn sharing_keys(
        &self,
        app_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<KeyResponse>, Error> {
        match self {
            Self::Http(c) => c.sharing_keys(app_key, offset, limit).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.sharing_keys(app_key, offset, limit).await,
        }
    }

    /// Retrieves one of the account's sharing keys by its public key.
    pub(crate) async fn sharing_key(
        &self,
        app_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<KeyResponse, Error> {
        match self {
            Self::Http(c) => c.sharing_key(app_key, public_key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.sharing_key(app_key, public_key).await,
        }
    }

    /// Deletes one of the account's sharing keys.
    pub(crate) async fn delete_sharing_key(
        &self,
        app_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        match self {
            Self::Http(c) => c.delete_sharing_key(app_key, public_key).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.delete_sharing_key(app_key, public_key).await,
        }
    }

    /// Attaches an object the account owns to one of its sharing keys.
    pub(crate) async fn add_shared_object(
        &self,
        app_key: &PrivateKey,
        sharing_key: &PublicKey,
        req: &SharedObjectRequest,
    ) -> Result<(), Error> {
        match self {
            Self::Http(c) => c.add_shared_object(app_key, sharing_key, req).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => c.add_shared_object(app_key, sharing_key, req).await,
        }
    }

    /// Lists the objects attached to one of the account's sharing keys.
    pub(crate) async fn sharing_key_objects(
        &self,
        app_key: &PrivateKey,
        sharing_key: &PublicKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<SealedObject>, Error> {
        match self {
            Self::Http(c) => {
                c.sharing_key_objects(app_key, sharing_key, offset, limit)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => {
                c.sharing_key_objects(app_key, sharing_key, offset, limit)
                    .await
            }
        }
    }

    /// Detaches an object from one of the account's sharing keys.
    pub(crate) async fn delete_shared_object(
        &self,
        app_key: &PrivateKey,
        sharing_key: &PublicKey,
        object_key: &Hash256,
    ) -> Result<(), Error> {
        match self {
            Self::Http(c) => {
                c.delete_shared_object(app_key, sharing_key, object_key)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(c) => {
                c.delete_shared_object(app_key, sharing_key, object_key)
                    .await
            }
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
    let mut state = Params::new().hash_length(32).to_state();
    state.update(method.as_str().as_bytes());
    state.update(host_port.as_bytes());
    state.update(url.path().as_bytes());
    state.update(&valid_until.timestamp().to_le_bytes());
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

    Params::new()
        .hash_length(32)
        .to_state()
        .update(KEY_DOMAIN)
        .update(ephemeral_key.as_ref())
        .update(request_id.as_bytes())
        .finalize()
        .into()
}

/// Computes the hash a pre-authorized key signs to approve a connection
/// request. It mirrors indexd's `preAuthorizationHash` and binds the proof to
/// this request's ephemeral key so a captured signature cannot be replayed with
/// a different one.
///
/// Strings are length-prefixed (matching sia core's `Encoder::WriteString`) and
/// keys and hashes are written as their raw 32 bytes. The field order follows
/// indexd's `Info` struct, which differs from the JSON serialization order.
fn pre_authorization_sig_hash(
    ephemeral_key: &PublicKey,
    meta: &AppMetadata,
    pre_authorized_key: &PublicKey,
) -> Hash256 {
    fn write_string(h: &mut blake2b_simd::State, s: &str) {
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }

    let mut h = Params::new().hash_length(32).to_state();
    write_string(&mut h, "indexd/preauthorize-app/v1");
    h.update(ephemeral_key.as_ref());
    h.update(meta.id.as_ref());
    write_string(&mut h, meta.name);
    write_string(&mut h, meta.description);
    write_string(&mut h, meta.logo_url.unwrap_or(""));
    write_string(&mut h, meta.service_url);
    write_string(&mut h, meta.callback_url.unwrap_or(""));
    h.update(pre_authorized_key.as_ref());
    h.finalize().into()
}

/// Pure computation tests (signing, hashing, encoding) — run on both native and WASM.
#[cfg(test)]
mod cross_target_test {
    use base64::engine::general_purpose::URL_SAFE;
    use sia_core::{hash_256, public_key, signature};

    use crate::slabs::SlabVersion::V0;
    use crate::slabs::object_id;
    use crate::time::Duration;

    use super::*;

    /// Golden CBOR `Account` response, shared with the HTTP tests.
    pub(super) const ACCOUNT_CBOR: &str = "a86a6163636f756e744b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f6d6d617850696e6e6564446174611b00000100000000007072656d61696e696e6753746f726167651a40000000657265616479f56a70696e6e656444617461006a70696e6e656453697a650063617070a56269645820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f646e616d656874657374206170706b6465736372697074696f6e60676c6f676f55524c606a7365727669636555524c60686c61737455736564781e323032362d31302d30325431323a33343a35362e3132333435363738395a";
    /// Golden CBOR `AuthConnectStatusResponse` for an approved, reconnecting
    /// request, shared with the HTTP tests.
    pub(super) const STATUS_CBOR: &str = "a368617070726f766564f56c7265636f6e6e656374696e67f56a757365725365637265745820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[sia_core_derive::cross_target_test]
    fn test_cbor_wire_format_golden() {
        // Generated from indexd's response types with fxamacker/cbor v2.9.3
        // against go.sia.tech/core v0.21.7. hash = 0..32, public key = 32..64,
        // nonce = 64..96, encryption key = 96..128, signature = 128..192.
        fn check<T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
            name: &str,
            cbor: &str,
            expected: T,
        ) {
            let decoded: T = ciborium::from_reader(hex::decode(cbor).unwrap().as_slice())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(decoded, expected, "{name}");
        }

        let hash = Hash256::new(std::array::from_fn(|i| i as u8));
        let key = PublicKey::new(std::array::from_fn(|i| i as u8 + 32));
        let nonce = Nonce(std::array::from_fn(|i| i as u8 + 64));
        let encryption_key =
            EncryptionKey::from(std::array::from_fn::<u8, 32, _>(|i| i as u8 + 96));
        let sig = Signature::from(std::array::from_fn::<u8, 64, _>(|i| i as u8 + 128));
        let now: DateTime<Utc> = "2026-10-02T12:34:56.123456789Z".parse().unwrap();
        let sectors = vec![Sector {
            root: hash,
            host_key: key,
        }];
        let slabs = vec![Slab {
            version: SlabVersion::V1,
            encryption_key: encryption_key.clone(),
            min_shards: 1,
            sectors: sectors.clone(),
            offset: 10,
            length: 100,
        }];
        let object = SealedObject {
            encrypted_data_key: vec![1, 2, 3],
            slabs: slabs.clone(),
            data_signature: sig.clone(),
            encrypted_metadata_key: vec![4, 5, 6],
            encrypted_metadata: vec![7, 8, 9],
            metadata_signature: sig.clone(),
            created_at: now,
            updated_at: now,
        };
        let stats = KeyStats {
            object_count: 3,
            object_size: 100,
            pinned_data: 200,
            pinned_size: 300,
            expires_at: None,
            created_at: now,
            updated_at: now,
        };

        check(
            "object",
            "a870656e63727970746564446174614b65794301020365736c61627381a66776657273696f6e016d656e6372797074696f6e4b65795820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f696d696e5368617264730167736563746f727381a264726f6f745820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f67686f73744b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f666f66667365740a666c656e67746818646d646174615369676e61747572655840808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf74656e637279707465644d657461646174614b65794304050671656e637279707465644d6574616461746143070809716d657461646174615369676e61747572655840808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf69637265617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a69757064617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a",
            object.clone(),
        );
        check(
            "key",
            "ab676163636f756e745820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f697075626c69634b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f656e6f6e63655820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6b6465736372697074696f6e6874657374206b65796b6f626a656374436f756e74036a6f626a65637453697a6518646a70696e6e65644461746118c86a70696e6e656453697a6519012c69657870697265734174781e323032362d31302d30325431323a33343a35362e3132333435363738395a69637265617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a69757064617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a",
            KeyResponse {
                public_key: key,
                nonce,
                account: key,
                description: "test key".to_string(),
                stats: KeyStats {
                    expires_at: Some(now),
                    ..stats.clone()
                },
            },
        );
        check(
            "host",
            "a7697075626c69634b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f6961646472657373657381a26870726f746f636f6c667369616d7578676164647265737375686f73742e6578616d706c652e636f6d3a393938346b636f756e747279436f6465625553686c61746974756465fb0000000000000000696c6f6e676974756465fb00000000000000006d676f6f64466f7255706c6f6164f565746f6b656ea467686f73744b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f676163636f756e745820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f6a76616c6964556e74696c781e323032362d31302d30325431323a33343a35362e3132333435363738395a697369676e61747572655840808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            SharedHost {
                host: Host {
                    public_key: key,
                    addresses: vec![sia_core::types::v2::NetAddress {
                        protocol: sia_core::types::v2::Protocol::SiaMux,
                        address: "host.example.com:9984".to_string(),
                    }],
                    country_code: "US".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    good_for_upload: true,
                },
                token: AccountToken {
                    host_key: key,
                    account: key,
                    valid_until: now,
                    signature: sig.clone(),
                },
            },
        );
        check(
            "account",
            ACCOUNT_CBOR,
            Account {
                account_key: key,
                max_pinned_data: 1 << 40,
                remaining_storage: 1 << 30,
                pinned_data: 0,
                pinned_size: 0,
                ready: true,
                app: crate::App {
                    id: hash,
                    name: "test app".to_string(),
                    description: String::new(),
                    logo_url: Some(String::new()),
                    service_url: Some(String::new()),
                },
                last_used: now,
            },
        );
        check(
            "status",
            STATUS_CBOR,
            AuthConnectStatusResponse {
                approved: true,
                reconnecting: true,
                user_secret: Some(hash),
            },
        );
        check(
            "events",
            "82a4636b65795820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f6764656c65746564f469757064617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a666f626a656374a870656e63727970746564446174614b65794301020365736c61627381a66776657273696f6e016d656e6372797074696f6e4b65795820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f696d696e5368617264730167736563746f727381a264726f6f745820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f67686f73744b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f666f66667365740a666c656e67746818646d646174615369676e61747572655840808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf74656e637279707465644d657461646174614b65794304050671656e637279707465644d6574616461746143070809716d657461646174615369676e61747572655840808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf69637265617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a69757064617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395aa3636b65795820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f6764656c65746564f569757064617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a",
            vec![
                SealedObjectEvent {
                    id: hash,
                    deleted: false,
                    updated_at: now,
                    object: Some(object),
                },
                SealedObjectEvent {
                    id: hash,
                    deleted: true,
                    updated_at: now,
                    object: None,
                },
            ],
        );
        check(
            "register",
            "a46b726573706f6e736555524c782a68747470733a2f2f696e64657865722e6578616d706c652e636f6d2f617574682f636f6e6e6563742f316973746174757355524c783168747470733a2f2f696e64657865722e6578616d706c652e636f6d2f617574682f636f6e6e6563742f312f7374617475736b726567697374657255524c783368747470733a2f2f696e64657865722e6578616d706c652e636f6d2f617574682f636f6e6e6563742f312f72656769737465726a65787069726174696f6e781e323032362d31302d30325431323a33343a35362e3132333435363738395a",
            RegisterAppResponse {
                response_url: "https://indexer.example.com/auth/connect/1".to_string(),
                status_url: "https://indexer.example.com/auth/connect/1/status".to_string(),
                register_url: "https://indexer.example.com/auth/connect/1/register".to_string(),
                expiration: now,
            },
        );
        check(
            "slab ids",
            "815820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            vec![hash],
        );
        check(
            "stats",
            "a66b6f626a656374436f756e74036a6f626a65637453697a6518646a70696e6e65644461746118c86a70696e6e656453697a6519012c69637265617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a69757064617465644174781e323032362d31302d30325431323a33343a35362e3132333435363738395a",
            stats,
        );
        check(
            "shared",
            "a165736c61627381a66776657273696f6e016d656e6372797074696f6e4b65795820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f696d696e5368617264730167736563746f727381a264726f6f745820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f67686f73744b65795820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f666f66667365740a666c656e6774681864",
            SharedObjectResponse {
                slabs,
                encrypted_metadata: None,
            },
        );
        // Go's zero time and nil slices encode as null.
        check(
            "zero",
            "a670656e63727970746564446174614b65794301020365736c616273f66d646174615369676e6174757265584000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000716d657461646174615369676e617475726558400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069637265617465644174f669757064617465644174f6",
            SealedObject {
                encrypted_data_key: vec![1, 2, 3],
                slabs: vec![],
                data_signature: Signature::default(),
                encrypted_metadata_key: vec![],
                encrypted_metadata: vec![],
                metadata_signature: Signature::default(),
                created_at: "0001-01-01T00:00:00Z".parse().unwrap(),
                updated_at: "0001-01-01T00:00:00Z".parse().unwrap(),
            },
        );
    }

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

    #[sia_core_derive::cross_target_test]
    fn test_pre_authorization_sig_hash_golden() {
        // Generated from indexd's api/app.preAuthorizationHash against
        // go.sia.tech/core v0.21.7. ephemeral seed = [1; 32], pre-auth seed = [2; 32].
        const EPHEMERAL: PublicKey =
            public_key!("ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c");
        let pre_auth_key = PrivateKey::from_seed(&[0x02u8; 32]);
        assert_eq!(
            pre_auth_key.public_key(),
            public_key!("ed25519:8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"),
            "pre-auth public key derivation mismatch"
        );

        // Case 1: every URL populated.
        const META_FULL: AppMetadata = AppMetadata {
            id: hash_256!("0e90d697f5045a6593f1c43ebf79a369e2bc72cc5c7b6282f3b5aeb0de6e4005"),
            name: "My App",
            description: "My App Description",
            service_url: "https://myapp.com",
            logo_url: Some("https://myapp.com/logo.png"),
            callback_url: Some("https://myapp.com/callback"),
        };
        let hash_full =
            pre_authorization_sig_hash(&EPHEMERAL, &META_FULL, &pre_auth_key.public_key());
        assert_eq!(
            hash_full,
            hash_256!("eeaf84c91b1cb3b12112eb70f3153f5444472c6626ac6713172e9ea882a9f992"),
            "full-metadata pre-auth hash mismatch"
        );
        // Full client path: signing the hash must reproduce Go's signature exactly.
        assert_eq!(
            pre_auth_key.sign(hash_full.as_ref()),
            signature!(
                "0f70578e17619e53f3a5ba16bacfd105d3b730eb8e02aa543d5f6f4340bca67d4b4c61de4d47641aff64a9955b4b4367de8c51448f1f48cbdb575bfb1d63a302"
            ),
            "pre-auth signature mismatch"
        );

        // Case 2: logo_url/callback_url = None must hash as empty strings.
        const META_EMPTY: AppMetadata = AppMetadata {
            id: hash_256!("0e90d697f5045a6593f1c43ebf79a369e2bc72cc5c7b6282f3b5aeb0de6e4005"),
            name: "My App",
            description: "My App Description",
            service_url: "https://myapp.com",
            logo_url: None,
            callback_url: None,
        };
        assert_eq!(
            pre_authorization_sig_hash(&EPHEMERAL, &META_EMPTY, &pre_auth_key.public_key()),
            hash_256!("e7b052984db5a3669a75339a665bfe085b4613d11e71728bb7efd31b877dbd76"),
            "empty-url pre-auth hash mismatch"
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

    #[sia_core_derive::cross_target_test]
    fn test_slab_pin_params_digest() {
        for version in [SlabVersion::V0, SlabVersion::V1] {
            let slab = Slab {
                version,
                encryption_key: [1u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([2u8; 32]),
                    host_key: PublicKey::new([3u8; 32]),
                }],
                offset: 123,
                length: 456,
            };
            let mut params = SlabPinParams::from(&slab);
            assert_eq!(params.digest(), slab.digest());
            params.sectors[0].uploaded_at = Some(Utc::now());
            assert_eq!(
                params.digest(),
                slab.digest(),
                "upload time changed the slab ID"
            );
            assert_eq!(
                Slab::from(&params),
                Slab {
                    offset: 0,
                    length: 0,
                    ..slab
                },
                "pin parameters changed the slab contents"
            );
        }
    }

    #[sia_core_derive::cross_target_test]
    fn test_is_slab_upload_too_old() {
        let message = "invalid slab pin params: slab 0: sector 3 invalid: slab upload is too old (max 48h0m0s)";
        let stale = Error::Api(StatusCode::BAD_REQUEST, message.into());
        assert!(stale.is_slab_upload_too_old());
        assert!(!stale.is_retryable());

        for error in [
            Error::Api(StatusCode::INTERNAL_SERVER_ERROR, message.into()),
            Error::Api(StatusCode::UNAUTHORIZED, message.into()),
            Error::Custom(message.into()),
            Error::Api(
                StatusCode::BAD_REQUEST,
                "slab upload time is in the future (max 5m0s ahead)".into(),
            ),
            Error::Api(StatusCode::BAD_REQUEST, "invalid slab pin params".into()),
        ] {
            assert!(!error.is_slab_upload_too_old(), "{error}");
        }
    }
}
