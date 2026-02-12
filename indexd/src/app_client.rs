use base64::engine::general_purpose::URL_SAFE;
use base64::prelude::*;
use std::time::Duration;

use async_trait::async_trait;
use blake2::Digest;
use chrono::{DateTime, Utc};
use reqwest::{Method, StatusCode};
use serde_json::to_vec;
use serde_with::base64::Base64;
use serde_with::serde_as;
use sia::blake2::Blake2b256;
use sia::encryption::EncryptionKey;
use sia::rhp::Host;

use thiserror::Error;

use serde::de::DeserializeOwned;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::object_encryption::DecryptError;
use crate::slabs::Sector;
use crate::{Object, PinnedSlab, SealedObject, Slab};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use sia::types::v2::Protocol;

pub use reqwest::{IntoUrl, Url};

const QUERY_PARAM_VALID_UNTIL: &str = "sv";
const QUERY_PARAM_CREDENTIAL: &str = "sc";
const QUERY_PARAM_SIGNATURE: &str = "ss";

#[derive(Debug, Error)]
pub enum Error {
    #[error("indexd responded with an error: {0}")]
    Api(String),

    #[error("invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("user rejected connection request")]
    UserRejected,

    #[error("format error: {0}")]
    Format(String),

    #[error("decryption error: {0}")]
    Decryption(#[from] DecryptError),

    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthConnectStatusResponse {
    approved: bool,
    user_secret: Option<Hash256>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAppRequest {
    #[serde(rename = "appID")]
    pub app_id: Hash256,
    pub name: String,
    pub description: String,
    #[serde(rename = "serviceURL")]
    pub service_url: Url,
    #[serde(rename = "logoURL")]
    pub logo_url: Option<Url>,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<Url>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAppResponse {
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
pub struct SlabPinParams {
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

pub struct ObjectsCursor {
    pub after: DateTime<Utc>,
    pub id: Hash256,
}

/// An SealedObjectEvent represents an object and whether it was deleted or not.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SealedObjectEvent {
    #[serde(rename = "key")]
    pub id: Hash256,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
    pub object: Option<SealedObject>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

impl Serialize for GeoLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let formatted = format!("({:.6},{:.6})", self.latitude, self.longitude);
        serializer.serialize_str(&formatted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostSort {
    Distance(GeoLocation),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct HostQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<GeoLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct App {
    pub id: Hash256,
    pub description: String,
    pub logo_url: Option<String>,
    pub service_url: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account_key: PublicKey,
    pub connect_key: String,
    pub max_pinned_data: u64,
    pub pinned_data: u64,
    pub app: App,
    pub last_used: DateTime<Utc>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharedObjectResponse {
    pub slabs: Vec<Slab>,
    #[serde_as(as = "Option<Base64>")]
    pub encrypted_metadata: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct Client {
    client: reqwest::Client,
    url: Url,
}

#[async_trait]
pub trait AppClient: Send + Sync {
    async fn check_app_authenticated(&self, app_key: &PrivateKey) -> Result<bool, Error>;

    async fn request_app_connection(
        &self,
        opts: &RegisterAppRequest,
    ) -> Result<RegisterAppResponse, Error>;

    async fn check_request_status(&self, status_url: Url) -> Result<Option<Hash256>, Error>;

    async fn register_app(&self, app_key: &PrivateKey, register_url: Url) -> Result<(), Error>;

    async fn hosts(&self, app_key: &PrivateKey, query: HostQuery) -> Result<Vec<Host>, Error>;

    async fn object(&self, app_key: &PrivateKey, key: &Hash256) -> Result<SealedObject, Error>;

    async fn objects(
        &self,
        app_key: &PrivateKey,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<SealedObjectEvent>, Error>;

    async fn save_object(&self, app_key: &PrivateKey, object: &SealedObject) -> Result<(), Error>;

    async fn delete_object(&self, app_key: &PrivateKey, key: &Hash256) -> Result<(), Error>;

    async fn slab(&self, app_key: &PrivateKey, slab_id: &Hash256) -> Result<PinnedSlab, Error>;

    async fn slab_ids(
        &self,
        app_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<Hash256>, Error>;

    async fn pin_slabs(
        &self,
        app_key: &PrivateKey,
        slabs: Vec<SlabPinParams>,
    ) -> Result<Vec<Hash256>, Error>;

    async fn pin_slab(&self, app_key: &PrivateKey, slab: SlabPinParams) -> Result<Hash256, Error>;

    async fn unpin_slab(&self, app_key: &PrivateKey, slab_id: &Hash256) -> Result<(), Error>;

    async fn prune_slabs(&self, app_key: &PrivateKey) -> Result<(), Error>;

    async fn account(&self, app_key: &PrivateKey) -> Result<Account, Error>;

    fn shared_object_url(
        &self,
        app_key: &PrivateKey,
        object: &Object,
        valid_until: DateTime<Utc>,
    ) -> Result<Url, Error>;

    async fn shared_object(&self, share_url: Url) -> Result<Object, Error>;
}

/// A placeholder type that implements serde::Deserialize for endpoints that
/// return no content.
struct EmptyResponse;

impl<'de> serde::Deserialize<'de> for EmptyResponse {
    fn deserialize<D>(_: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(EmptyResponse)
    }
}

impl Client {
    pub fn new<U: IntoUrl>(base_url: U) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            url: base_url.into_url()?,
        })
    }

    /// Checks if the application is authenticated with the indexer. It returns
    /// true if authenticated, false if not, and an error if the request fails.
    pub async fn check_app_authenticated(&self, app_key: &PrivateKey) -> Result<bool, Error> {
        let url = self.url.join("auth/check")?;
        let query_params = self.sign(
            app_key,
            &url,
            Method::GET,
            None,
            Utc::now() + Duration::from_secs(60),
        );
        let resp = self
            .client
            .get(url)
            .timeout(Duration::from_secs(15))
            .query(&query_params)
            .send()
            .await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::NO_CONTENT => Ok(true),
            _ => Err(Error::Api(resp.text().await?)),
        }
    }

    /// Requests an application connection to the indexer.
    pub async fn request_app_connection(
        &self,
        opts: &RegisterAppRequest,
    ) -> Result<RegisterAppResponse, Error> {
        self.post_json("auth/connect", None, Some(opts)).await
    }

    /// Checks if an auth request has been approved.
    ///
    /// If approved, it returns the user secret used
    /// to derive the application key.
    ///
    /// If the auth request is still pending, it returns None.
    pub async fn check_request_status(&self, status_url: Url) -> Result<Option<Hash256>, Error> {
        let resp = self
            .client
            .get(status_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => {
                if let Ok(status) = resp.json::<AuthConnectStatusResponse>().await {
                    if status.approved {
                        Ok(status.user_secret)
                    } else {
                        Ok(None)
                    }
                } else {
                    Err(Error::Api("invalid response format".to_string()))
                }
            }
            StatusCode::NOT_FOUND => Err(Error::UserRejected),
            _ => Err(Error::Api(resp.text().await?)),
        }
    }

    /// Registers the application key with the indexer.
    pub async fn register_app(&self, app_key: &PrivateKey, register_url: Url) -> Result<(), Error> {
        let query_params = self.sign(
            app_key,
            &register_url,
            Method::POST,
            None,
            Utc::now() + Duration::from_secs(60),
        );
        let resp = self
            .client
            .post(register_url)
            .timeout(Duration::from_secs(15))
            .query(&query_params)
            .send()
            .await?;
        match resp.status() {
            StatusCode::NO_CONTENT => Ok(()),
            _ => Err(Error::Api(resp.text().await?)),
        }
    }

    /// Returns all usable hosts.
    ///
    /// # Arguments
    /// * `query` - Parameters to control the hosts listing.
    pub async fn hosts(&self, app_key: &PrivateKey, query: HostQuery) -> Result<Vec<Host>, Error> {
        self.get_json("hosts", Some(app_key), Some(&query)).await
    }

    /// Retrieves an object from the indexer by its key.
    pub async fn object(&self, app_key: &PrivateKey, key: &Hash256) -> Result<SealedObject, Error> {
        self.get_json::<_, ()>(&format!("objects/{key}"), Some(app_key), None)
            .await
    }

    /// Fetches a list of objects from the indexer. Can be paginated using the
    /// cursor and limit arguments.
    pub async fn objects(
        &self,
        app_key: &PrivateKey,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<SealedObjectEvent>, Error> {
        let mut query_params = Vec::new();
        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(ObjectsCursor { after, id }) = cursor {
            query_params.push(("after", after.to_rfc3339())); // indexd expects RFC3339
            query_params.push(("key", id.to_string()));
        }
        self.get_json::<_, _>("objects", Some(app_key), Some(&query_params))
            .await
    }

    /// Saves an object to the indexer.
    pub async fn save_object(
        &self,
        app_key: &PrivateKey,
        object: &SealedObject,
    ) -> Result<(), Error> {
        self.post_json::<_, EmptyResponse>("objects", Some(app_key), Some(object))
            .await
            .map(|_| ())
    }

    /// Deletes an object from the indexer by its key.
    pub async fn delete_object(&self, app_key: &PrivateKey, key: &Hash256) -> Result<(), Error> {
        self.delete(&format!("objects/{key}"), app_key).await
    }

    /// Retrieves a slab from the indexer by its ID.
    pub async fn slab(&self, app_key: &PrivateKey, slab_id: &Hash256) -> Result<PinnedSlab, Error> {
        self.get_json::<_, ()>(&format!("slabs/{slab_id}"), Some(app_key), None)
            .await
    }

    /// Fetches the digests of slabs associated with the account. It supports
    /// pagination through the provided options.
    pub async fn slab_ids(
        &self,
        app_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<Hash256>, Error> {
        #[derive(Serialize)]
        struct QueryParams {
            offset: Option<u64>,
            limit: Option<u64>,
        }
        let params = QueryParams { offset, limit };
        self.get_json("slabs", Some(app_key), Some(&params)).await
    }

    /// Pins slabs to the indexer.
    pub async fn pin_slabs(
        &self,
        app_key: &PrivateKey,
        slabs: Vec<SlabPinParams>,
    ) -> Result<Vec<Hash256>, Error> {
        self.post_json("slabs", Some(app_key), Some(&slabs)).await
    }

    /// Pin a slab to the indexer.
    pub async fn pin_slab(
        &self,
        app_key: &PrivateKey,
        slab: SlabPinParams,
    ) -> Result<Hash256, Error> {
        self.pin_slabs(app_key, vec![slab])
            .await?
            .into_iter()
            .next()
            .ok_or(Error::Custom("no slab digest".to_string()))
    }

    /// Unpins a slab from the indexer.
    pub async fn unpin_slab(&self, app_key: &PrivateKey, slab_id: &Hash256) -> Result<(), Error> {
        self.delete(&format!("slabs/{slab_id}"), app_key).await
    }

    /// Unpins slabs not used by any object on the account.
    pub async fn prune_slabs(&self, app_key: &PrivateKey) -> Result<(), Error> {
        self.post_json::<(), EmptyResponse>("slabs/prune", Some(app_key), None)
            .await
            .map(|_| ())
    }

    /// Account returns the current account.
    pub async fn account(&self, app_key: &PrivateKey) -> Result<Account, Error> {
        self.get_json::<_, ()>("account", Some(app_key), None).await
    }

    /// Helper to send a signed DELETE request.
    async fn delete(&self, path: &str, app_key: &PrivateKey) -> Result<(), Error> {
        let url = self.url.join(path)?;
        let query_params = self.sign(
            app_key,
            &url,
            Method::DELETE,
            None,
            Utc::now() + Duration::from_secs(60),
        );
        Self::handle_response::<EmptyResponse>(
            self.client
                .delete(url)
                .timeout(Duration::from_secs(15))
                .query(&query_params)
                .send()
                .await?,
        )
        .await
        .map(|_| ())
    }

    /// Helper to send a signed GET request and parse the JSON
    /// response.
    async fn get_json<D: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        path: &str,
        app_key: Option<&PrivateKey>,
        query_params: Option<&Q>,
    ) -> Result<D, Error> {
        let url = self.url.join(path)?;

        let mut signing_params = None;
        if let Some(app_key) = app_key {
            let params = self.sign(
                app_key,
                &url,
                Method::GET,
                None,
                Utc::now() + Duration::from_secs(60),
            );
            signing_params = Some(params);
        }

        let mut builder = self.client.get(url).timeout(Duration::from_secs(15));
        if let Some(q) = query_params {
            builder = builder.query(q); // optional query params
        }
        if let Some(signing_params) = &signing_params {
            builder = builder.query(&signing_params);
        }
        Self::handle_response(builder.send().await?).await
    }

    /// Helper to either parse a successfully JSON response or return the error
    /// message from the API.
    async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, Error> {
        if resp.status().is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            Err(Error::Api(resp.text().await?))
        }
    }

    // Helper to send a signed POST request and parse the JSON
    // response.
    async fn post_json<S: Serialize, D: DeserializeOwned>(
        &self,
        path: &str,
        app_key: Option<&PrivateKey>,
        body: Option<&S>,
    ) -> Result<D, Error> {
        let body = body.and_then(|body| to_vec(body).ok());
        let url = self.url.join(path)?;

        let mut query_params = None;
        if let Some(app_key) = app_key {
            query_params = Some(self.sign(
                app_key,
                &url,
                Method::POST,
                body.as_deref(),
                Utc::now() + Duration::from_secs(60),
            ));
        }

        let mut builder = self.client.post(url).timeout(Duration::from_secs(15));
        if let Some(query_params) = &query_params {
            builder = builder.query(&query_params);
        }
        if let Some(body) = body {
            builder = builder.body(body);
        }
        Self::handle_response(builder.send().await?).await
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

    /// Creates a signed url that can be shared with others
    /// to give read access to a single object. An expired
    /// link does not necessarily remove access to an object.
    ///
    /// # Arguments
    /// - `object` the object to create the link for
    /// - `valid_until` the time the link expires
    pub fn shared_object_url(
        &self,
        app_key: &PrivateKey,
        object: &Object,
        valid_until: DateTime<Utc>,
    ) -> Result<Url, Error> {
        let mut url = self
            .url
            .join(format!("objects/{}/shared", object.id()).as_str())?;

        let params = self.sign(app_key, &url, Method::GET, None, valid_until);
        url.set_fragment(Some(
            format!(
                "encryption_key={}",
                URL_SAFE.encode(object.data_key().as_ref())
            )
            .as_str(),
        ));

        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value.as_str());
        }

        Ok(pairs.finish().to_owned())
    }

    /// Retrieves the object metadata using a pre-signed url
    ///
    /// # Arguments
    /// `share_url` a pre-signed url for the App objects API
    ///
    /// # Returns
    /// A tuple with the object metadata and encryption key to decrypt
    /// the user metadata.
    pub async fn shared_object(&self, mut share_url: Url) -> Result<Object, Error> {
        let encryption_key = match share_url.fragment() {
            Some(fragment) => {
                let fragment = match fragment.strip_prefix("encryption_key=") {
                    Some(fragment) => Ok(fragment),
                    None => Err(Error::Format("missing encryption_key".into())),
                }?;
                let mut out = [0u8; 32];
                URL_SAFE.decode_slice(fragment, &mut out).map_err(|_| {
                    Error::Format("encryption key must be 32 hex-encoded bytes".into())
                })?;
                Ok(EncryptionKey::from(out))
            }
            None => Err(Error::Format("missing encryption_key".into())),
        }?;
        share_url.set_fragment(None);
        let shared_object: SharedObjectResponse = Self::handle_response(
            self.client
                .get(share_url)
                .timeout(Duration::from_secs(15))
                .send()
                .await?,
        )
        .await?;

        Ok(Object::new(
            encryption_key,
            shared_object.slabs.clone(),
            Vec::new(),
        ))
    }

    fn sign(
        &self,
        app_key: &PrivateKey,
        url: &Url,
        method: Method,
        body: Option<&[u8]>,
        valid_until: DateTime<Utc>,
    ) -> [(&'static str, String); 3] {
        let hash = Self::request_hash(url, method, body, valid_until);
        let public_key = app_key.public_key();
        let signature = app_key.sign(hash.as_ref());
        [
            (QUERY_PARAM_VALID_UNTIL, valid_until.timestamp().to_string()),
            (QUERY_PARAM_CREDENTIAL, URL_SAFE.encode(public_key)),
            (QUERY_PARAM_SIGNATURE, URL_SAFE.encode(signature.as_ref())),
        ]
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE;
    use base64::prelude::*;
    use chrono::FixedOffset;
    use sia::signing::Signature;
    use sia::{hash_256, public_key, signature};

    use crate::object_id;

    use super::*;
    use httptest::http::Response;
    use httptest::matchers::*;
    use httptest::{Expectation, Server};

    /// Ensures that our base64 url encoding is compatible with our Go implementation.
    #[test]
    fn test_base64_url() {
        const DATA: &[u8] = b"hello, world!";
        const ENCODED_DATA: &str = "aGVsbG8sIHdvcmxkIQ==";

        let encoded = URL_SAFE.encode(DATA);
        assert_eq!(encoded, ENCODED_DATA);
    }

    #[test]
    fn test_request_hash() {
        let method = Method::POST;
        let url = Url::parse("https://foo.bar/foo").unwrap();
        let valid_until = DateTime::from_timestamp_secs(123).unwrap();
        let body = b"hello world!";
        let hash = Client::request_hash(&url, method, Some(body), valid_until);
        assert_eq!(
            hash,
            hash_256!("a9f0bda1b97b7d44ae6369ac830851a115311bb59aa2d848beda6ae95d10ad18")
        )
    }

    #[test]
    fn test_sign() {
        let app_key = PrivateKey::from_seed(&[0u8; 32]);
        let client = Client::new("https://foo.bar").unwrap();

        // with body
        let params = client.sign(
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
        let params = client.sign(
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

    #[tokio::test]
    async fn test_signed_auth() {
        let server = Server::run();

        // expect 1 authenticated get and 1 authenticated post request
        server.expect(
            Expectation::matching(request::query(url_decoded(all_of![
                contains((QUERY_PARAM_VALID_UNTIL, any())),
                contains((QUERY_PARAM_CREDENTIAL, any())),
                contains((QUERY_PARAM_SIGNATURE, any()))
            ])))
            .times(3)
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("{}")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        let _: Result<(), _> = client.get_json::<_, ()>("", Some(&app_key), None).await;
        let _: Result<(), _> = client.post_json::<(), ()>("", Some(&app_key), None).await;
        let _: Result<(), _> = client.delete("", &app_key).await;
    }

    #[tokio::test]
    async fn test_hosts_with_distance_sort_adds_query() {
        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/hosts"),
                request::query(url_decoded(contains(("location", "(51.209300,3.224700)"))))
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("[]")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        let hosts = client
            .hosts(
                &app_key,
                HostQuery {
                    location: Some(GeoLocation {
                        latitude: 51.2093,
                        longitude: 3.2247,
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(hosts.is_empty());
    }

    #[tokio::test]
    async fn test_hosts_with_additional_filters() {
        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/hosts"),
                request::query(url_decoded(all_of![
                    contains(("offset", "5")),
                    contains(("limit", "25")),
                    contains(("protocol", "quic")),
                    contains(("country", "us"))
                ]))
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("[]")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        let hosts = client
            .hosts(
                &app_key,
                HostQuery {
                    offset: Some(5),
                    limit: Some(25),
                    protocol: Some(Protocol::QUIC),
                    country: Some("us".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(hosts.is_empty());
    }

    #[tokio::test]
    async fn test_slab() {
        let slab = PinnedSlab {
            id: "43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28"
                .parse()
                .unwrap(),
            encryption_key: [
                186, 153, 179, 170, 159, 95, 101, 177, 15, 130, 58, 19, 138, 144, 9, 91, 181, 119,
                38, 225, 209, 47, 149, 22, 157, 210, 16, 232, 10, 151, 186, 160,
            ]
            .into(),
            min_shards: 1,
            sectors: vec![Sector {
                root: hash_256!("826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6"),
                host_key: public_key!(
                    "ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe"
                ),
            }],
        };

        const TEST_SLAB_JSON: &str = r#"
        {
          "id": "43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28",
          "encryptionKey": "upmzqp9fZbEPgjoTipAJW7V3JuHRL5UWndIQ6AqXuqA=",
          "minShards": 1,
          "sectors": [
            {
              "root": "826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6",
              "hostKey": "ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe"
            }
          ]
        }
        "#;

        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/slabs/43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28",
            ))
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(TEST_SLAB_JSON)
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        assert_eq!(client.slab(&app_key, &slab.id).await.unwrap(), slab);
    }

    #[tokio::test]
    async fn test_slab_ids() {
        let slab_id = hash_256!("43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28");
        let server = Server::run();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/slabs"),
                request::query(url_decoded(all_of![
                    contains(("offset", "1")),
                    contains(("limit", "2"))
                ]))
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(format!(r#"["{slab_id}","{slab_id}"]"#))
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        assert_eq!(
            client.slab_ids(&app_key, Some(1), Some(2)).await.unwrap(),
            vec![slab_id, slab_id]
        );
    }

    #[tokio::test]
    async fn test_pin_slab() {
        let slab_id = hash_256!("43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28");
        let slab = SlabPinParams {
            encryption_key: [
                186, 153, 179, 170, 159, 95, 101, 177, 15, 130, 58, 19, 138, 144, 9, 91, 181, 119,
                38, 225, 209, 47, 149, 22, 157, 210, 16, 232, 10, 151, 186, 160,
            ]
            .into(),
            min_shards: 1,
            sectors: vec![Sector {
                root: hash_256!("826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6"),
                host_key: public_key!(
                    "ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe"
                ),
            }],
        };
        let server = Server::run();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/slabs"),
                request::body(serde_json::to_string(&vec![slab.clone()]).unwrap())
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("[\"43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28\"]")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        assert_eq!(client.pin_slab(&app_key, slab).await.unwrap(), slab_id);
    }

    #[tokio::test]
    async fn test_unpin_slab() {
        let slab_id = hash_256!("43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28");
        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path("DELETE", format!("/slabs/{slab_id}")))
                .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        client.unpin_slab(&app_key, &slab_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_prune_slabs() {
        let server = Server::run();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/slabs/prune"),
                request::body(""),
            ])
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        client.prune_slabs(&app_key).await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_response() {
        let server = Server::run();
        server.expect(
            Expectation::matching(any()).times(3).respond_with(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("something went wrong")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();

        let expected_error = Error::Api("something went wrong".to_string());
        let get_error = client
            .get_json::<(), ()>("", Some(&app_key), None)
            .await
            .unwrap_err();
        assert_eq!(get_error.to_string(), expected_error.to_string());
        let post_error = client
            .post_json::<(), ()>("", Some(&app_key), None)
            .await
            .unwrap_err();
        assert_eq!(post_error.to_string(), expected_error.to_string());
        let delete_error = client.delete("", &app_key).await.unwrap_err();
        assert_eq!(delete_error.to_string(), expected_error.to_string());
    }

    #[tokio::test]
    async fn test_check_request_status() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/approved")).respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("{\"approved\": true, \"userSecret\": \"3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2\"}")
                    .unwrap(),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/rejected")).respond_with(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body("")
                    .unwrap(),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/error")).respond_with(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("something went wrong")
                    .unwrap(),
            ),
        );

        let client = Client::new("https://foo.com").unwrap();

        // approved request
        let status_url: Url = server.url("/approved").to_string().parse().unwrap();
        assert_eq!(
            client
                .check_request_status(status_url)
                .await
                .unwrap()
                .unwrap(),
            hash_256!("3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2")
        );

        // rejected request
        let status_url: Url = server.url("/rejected").to_string().parse().unwrap();
        assert!(matches!(
            client.check_request_status(status_url).await.unwrap_err(),
            Error::UserRejected,
        ));

        // other error
        let status_url: Url = server.url("/error").to_string().parse().unwrap();
        let err = client.check_request_status(status_url).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "indexd responded with an error: something went wrong"
        );
    }

    #[tokio::test]
    async fn test_check_app_auth() {
        let server = Server::run();
        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("").to_string()).unwrap();

        // approved request
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check")).respond_with(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body("")
                    .unwrap(),
            ),
        );
        assert!(client.check_app_authenticated(&app_key).await.unwrap());

        // rejected request
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check")).respond_with(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("")
                    .unwrap(),
            ),
        );
        assert!(!client.check_app_authenticated(&app_key).await.unwrap());

        // other error
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check")).respond_with(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("something went wrong")
                    .unwrap(),
            ),
        );
        let err = client.check_app_authenticated(&app_key).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "indexd responded with an error: something went wrong"
        );
    }

    #[tokio::test]
    async fn test_request_app_connection() {
        let server = Server::run();
        let app_id = {
            let buf: [u8; 32] = rand::random();
            Hash256::from(buf)
        };
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/auth/connect"),
                request::body(format!(r#"{{"appID":"{app_id}","name":"name","description":"description","serviceURL":"https://service.com/","logoURL":"https://logo.com/","callbackURL":"https://callback.com/"}}"#)),
            ])
                .respond_with(Response::builder().status(StatusCode::OK).body(r#"{"responseURL":"https://response.com", "registerURL":"https://response.com","statusURL":"https://status.com","expiration":"1970-01-01T01:01:40+01:00"}"#).unwrap()),
        );

        let client = Client::new(server.url("/").to_string()).unwrap();

        let resp = client
            .request_app_connection(&RegisterAppRequest {
                app_id,
                name: "name".to_string(),
                description: "description".to_string(),
                service_url: "https://service.com".parse().unwrap(),
                logo_url: Some("https://logo.com".parse().unwrap()),
                callback_url: Some("https://callback.com".parse().unwrap()),
            })
            .await
            .unwrap();

        assert_eq!(
            resp,
            RegisterAppResponse {
                register_url: "https://response.com".to_string(),
                response_url: "https://response.com".to_string(),
                status_url: "https://status.com".to_string(),
                expiration: DateTime::from_timestamp_secs(100).unwrap(),
            }
        )
    }

    #[tokio::test]
    async fn test_object() {
        let object = SealedObject {
            encrypted_data_key: vec![1u8; 72],
            encrypted_metadata_key: vec![1u8; 72],
            encrypted_metadata: b"hello world!".to_vec(),
            data_signature: Signature::from([2u8; 64]),
            metadata_signature: Signature::from([2u8; 64]),
            slabs: vec![
                Slab {
                    encryption_key: [1u8; 32].into(),
                    min_shards: 1,
                    sectors: vec![
                        Sector {
                            root: hash_256!(
                                "0202020202020202020202020202020202020202020202020202020202020202"
                            ),
                            host_key: public_key!(
                                "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
                            ),
                        },
                        Sector {
                            root: hash_256!(
                                "0404040404040404040404040404040404040404040404040404040404040404"
                            ),
                            host_key: public_key!(
                                "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
                            ),
                        },
                    ],
                    offset: 6,
                    length: 7,
                },
                Slab {
                    encryption_key: [1u8; 32].into(),
                    min_shards: 1,
                    sectors: vec![
                        Sector {
                            root: hash_256!(
                                "0202020202020202020202020202020202020202020202020202020202020202"
                            ),
                            host_key: public_key!(
                                "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
                            ),
                        },
                        Sector {
                            root: hash_256!(
                                "0404040404040404040404040404040404040404040404040404040404040404"
                            ),
                            host_key: public_key!(
                                "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
                            ),
                        },
                    ],
                    offset: 6,
                    length: 7,
                },
            ],
            created_at: DateTime::<FixedOffset>::parse_from_rfc3339(
                "2025-09-09T16:10:46.898399-07:00",
            )
            .unwrap()
            .to_utc(),
            updated_at: DateTime::<FixedOffset>::parse_from_rfc3339(
                "2025-09-09T16:10:46.898399-07:00",
            )
            .unwrap()
            .to_utc(),
        };

        const TEST_OBJECT_JSON: &str = r#"
        {
          "encryptedDataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
          "encryptedMetadataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
          "slabs": [
           {
             "encryptionKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
             "minShards": 1,
             "sectors": [
               {
                 "root": "0202020202020202020202020202020202020202020202020202020202020202",
                 "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
               },
               {
                 "root": "0404040404040404040404040404040404040404040404040404040404040404",
                 "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
               }
             ],
             "offset": 6,
             "length": 7
           },
           {
             "encryptionKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
             "minShards": 1,
             "sectors": [
               {
                 "root": "0202020202020202020202020202020202020202020202020202020202020202",
                 "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
               },
               {
                 "root": "0404040404040404040404040404040404040404040404040404040404040404",
                 "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
               }
             ],
             "offset": 6,
             "length": 7
           }
          ],
          "encryptedMetadata": "aGVsbG8gd29ybGQh",
          "dataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
          "metadataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
          "createdAt": "2025-09-09T16:10:46.898399-07:00",
          "updatedAt": "2025-09-09T16:10:46.898399-07:00"
         }
        "#;

        let server = Server::run();
        let object_id = object.id();

        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/objects/{}", object_id),
            ))
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(TEST_OBJECT_JSON)
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        assert_eq!(client.object(&app_key, &object_id).await.unwrap(), object);
    }

    #[tokio::test]
    async fn test_objects() {
        let object = SealedObject {
            encrypted_data_key: vec![1u8; 72],
            encrypted_metadata_key: vec![1u8; 72],
            slabs: vec![
                Slab {
                    encryption_key: [1u8; 32].into(),
                    min_shards: 1,
                    sectors: vec![
                        Sector {
                            root: hash_256!(
                                "0202020202020202020202020202020202020202020202020202020202020202"
                            ),
                            host_key: public_key!(
                                "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
                            ),
                        },
                        Sector {
                            root: hash_256!(
                                "0404040404040404040404040404040404040404040404040404040404040404"
                            ),
                            host_key: public_key!(
                                "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
                            ),
                        },
                    ],
                    offset: 0,
                    length: 256,
                },
                Slab {
                    encryption_key: [2u8; 32].into(),
                    min_shards: 1,
                    sectors: vec![
                        Sector {
                            root: hash_256!(
                                "0202020202020202020202020202020202020202020202020202020202020202"
                            ),
                            host_key: public_key!(
                                "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
                            ),
                        },
                        Sector {
                            root: hash_256!(
                                "0404040404040404040404040404040404040404040404040404040404040404"
                            ),
                            host_key: public_key!(
                                "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
                            ),
                        },
                    ],
                    offset: 256,
                    length: 512,
                },
            ],
            encrypted_metadata: b"hello world!".to_vec(),
            data_signature: Signature::from([2u8; 64]),
            metadata_signature: Signature::from([2u8; 64]),
            created_at: DateTime::<FixedOffset>::parse_from_rfc3339(
                "2025-09-09T16:10:46.898399-07:00",
            )
            .unwrap()
            .to_utc(),
            updated_at: DateTime::<FixedOffset>::parse_from_rfc3339(
                "2025-09-09T16:10:46.898399-07:00",
            )
            .unwrap()
            .to_utc(),
        };
        let object_no_meta = SealedObject {
            encrypted_metadata: Vec::new(),
            ..object.clone()
        };

        const TEST_OBJECTS_JSON: &str = r#"
[
  {
    "key": "7f26b785c0dff73f51b81728289381064ad4b947f37417cbcb366afc3d80c7f5",
    "deleted": false,
    "updatedAt": "2025-09-09T16:10:46.898399-07:00",
    "object": {
      "encryptedDataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
      "encryptedMetadataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
      "slabs": [
        {
          "encryptionKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
          "minShards": 1,
          "sectors": [
            {
              "root": "0202020202020202020202020202020202020202020202020202020202020202",
              "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
            },
            {
              "root": "0404040404040404040404040404040404040404040404040404040404040404",
              "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
            }
          ],
          "offset": 0,
          "length": 256
        },
        {
          "encryptionKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
          "minShards": 1,
          "sectors": [
            {
              "root": "0202020202020202020202020202020202020202020202020202020202020202",
              "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
            },
            {
              "root": "0404040404040404040404040404040404040404040404040404040404040404",
              "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
            }
          ],
          "offset": 256,
          "length": 512
        }
      ],
      "encryptedMetadata": "aGVsbG8gd29ybGQh",
      "dataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "metadataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "createdAt": "2025-09-09T16:10:46.898399-07:00",
      "updatedAt": "2025-09-09T16:10:46.898399-07:00"
    }
  },
  {
    "key": "7f26b785c0dff73f51b81728289381064ad4b947f37417cbcb366afc3d80c7f5",
    "deleted": false,
    "updatedAt": "2025-09-09T16:10:46.898399-07:00",
    "object": {
      "encryptedDataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
      "encryptedMetadataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
      "slabs": [
        {
          "encryptionKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
          "minShards": 1,
          "sectors": [
            {
              "root": "0202020202020202020202020202020202020202020202020202020202020202",
              "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
            },
            {
              "root": "0404040404040404040404040404040404040404040404040404040404040404",
              "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
            }
          ],
          "offset": 0,
          "length": 256
        },
        {
          "encryptionKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
          "minShards": 1,
          "sectors": [
            {
              "root": "0202020202020202020202020202020202020202020202020202020202020202",
              "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
            },
            {
              "root": "0404040404040404040404040404040404040404040404040404040404040404",
              "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
            }
          ],
          "offset": 256,
          "length": 512
        }
      ],
      "encryptedMetadata": null,
      "dataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "metadataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "createdAt": "2025-09-09T16:10:46.898399-07:00",
      "updatedAt": "2025-09-09T16:10:46.898399-07:00"
    }
  },
  {
    "key": "7f26b785c0dff73f51b81728289381064ad4b947f37417cbcb366afc3d80c7f5",
    "deleted": false,
    "updatedAt": "2025-09-09T16:10:46.898399-07:00",
    "object": {
      "encryptedDataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
      "encryptedMetadataKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
      "slabs": [
        {
          "encryptionKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
          "minShards": 1,
          "sectors": [
            {
              "root": "0202020202020202020202020202020202020202020202020202020202020202",
              "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
            },
            {
              "root": "0404040404040404040404040404040404040404040404040404040404040404",
              "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
            }
          ],
          "offset": 0,
          "length": 256
        },
        {
          "encryptionKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
          "minShards": 1,
          "sectors": [
            {
              "root": "0202020202020202020202020202020202020202020202020202020202020202",
              "hostKey": "ed25519:0303030303030303030303030303030303030303030303030303030303030303"
            },
            {
              "root": "0404040404040404040404040404040404040404040404040404040404040404",
              "hostKey": "ed25519:0505050505050505050505050505050505050505050505050505050505050505"
            }
          ],
          "offset": 256,
          "length": 512
        }
      ],
      "dataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "metadataSignature": "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "createdAt": "2025-09-09T16:10:46.898399-07:00",
      "updatedAt": "2025-09-09T16:10:46.898399-07:00"
    }
  }
]
"#;

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/objects"),
                request::query(url_decoded(all_of![
                    contains(("after", "2025-09-09T23:10:46.898399+00:00")),
                    contains(("key", object.id().to_string())),
                    contains(("limit", "1")),
                ]))
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(TEST_OBJECTS_JSON)
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();

        assert_eq!(
            client
                .objects(
                    &app_key,
                    Some(ObjectsCursor {
                        after: object.updated_at.into(),
                        id: object.id(),
                    }),
                    Some(1)
                )
                .await
                .unwrap(),
            vec![
                SealedObjectEvent {
                    id: object.id(),
                    deleted: false,
                    updated_at: object.updated_at,
                    object: Some(object),
                },
                SealedObjectEvent {
                    id: object_no_meta.id(),
                    deleted: false,
                    updated_at: object_no_meta.updated_at,
                    object: Some(object_no_meta.clone()),
                },
                SealedObjectEvent {
                    id: object_no_meta.id(),
                    deleted: false,
                    updated_at: object_no_meta.updated_at,
                    object: Some(object_no_meta),
                },
            ]
        );
    }

    #[tokio::test]
    async fn delete_object() {
        let object_key =
            hash_256!("1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef");
        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path(
                "DELETE",
                "/objects/1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef",
            ))
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        client.delete_object(&app_key, &object_key).await.unwrap();
    }

    #[tokio::test]
    async fn save_object() {
        let object = SealedObject {
            encrypted_data_key: vec![1u8; 72],
            encrypted_metadata_key: vec![1u8; 72],
            data_signature: Signature::from([2u8; 64]),
            metadata_signature: Signature::from([2u8; 64]),
            slabs: vec![
                Slab {
                    encryption_key: [1u8; 32].into(),
                    min_shards: 2,
                    sectors: vec![],
                    offset: 0,
                    length: 256,
                },
                Slab {
                    encryption_key: [2u8; 32].into(),
                    min_shards: 2,
                    sectors: vec![],
                    offset: 256,
                    length: 512,
                },
            ],
            encrypted_metadata: b"hello world!".to_vec().into(),
            created_at: DateTime::<FixedOffset>::parse_from_rfc3339(
                "2025-09-09T16:10:46.898399-07:00",
            )
            .unwrap()
            .to_utc(),
            updated_at: DateTime::<FixedOffset>::parse_from_rfc3339(
                "2025-09-09T16:10:46.898399-07:00",
            )
            .unwrap()
            .to_utc(),
        };

        let server = Server::run();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/objects"),
                request::body(serde_json::to_string(&object).unwrap())
            ])
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        client.save_object(&app_key, &object).await.unwrap();
    }

    #[test]
    fn test_shared_object_id() {
        let obj = SharedObjectResponse {
            slabs: vec![Slab {
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
