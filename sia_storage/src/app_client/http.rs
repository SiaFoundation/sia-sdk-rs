use base64::engine::general_purpose::URL_SAFE;
use base64::prelude::*;
use chrono::{DateTime, Utc};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::to_vec;
use sia_core::signing::{PrivateKey, PublicKey};
use sia_core::types::Hash256;

use super::{
    AppConnectRequest, AuthApproval, AuthConnectStatusResponse, Error, IntoUrl, KeyResponse,
    PinObjectRequest, RegisterAppRequest, RegisterAppResponse, SHARE_URL_FETCH_SCHEME,
    SHARE_URL_SCHEME, SealedObjectEvent, SharedHost, SharedObjectResponse, SlabPinParams, Url,
    pre_authorization_sig_hash, register_app_sig_hash, sign,
};
use crate::app_client::{ERROR_OBJECT_UNPINNED_SLAB, PinObjectError};
use crate::encryption::EncryptionKey;
use crate::hosts::Host;
use crate::sharing::{KeyRequest, SharedObjectRequest};
use crate::slabs::SealedObjectSummary;
use crate::time::Duration;
use crate::{Account, AppMetadata, HostQuery, KeyStats, Object, ObjectsCursor, SealedObject};

const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(45);
const ACCEPT_CBOR: &str = "application/cbor, application/json;q=0.9";
const ACCEPT_JSON: &str = "application/json";

#[derive(Clone)]
pub(crate) struct Client {
    client: reqwest::Client,
    url: Url,
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
    pub(crate) fn new<U: IntoUrl>(base_url: U) -> Result<Self, Error> {
        Ok(Self {
            client: http_client(true),
            url: base_url.into_url()?,
        })
    }

    pub(crate) fn set_cbor(&mut self, enable: bool) {
        self.client = http_client(enable);
    }

    /// Checks if the application is authenticated with the indexer. It returns
    /// true if authenticated, false if not, and an error if the request fails.
    pub(crate) async fn check_app_authenticated(
        &self,
        app_key: &PrivateKey,
    ) -> Result<bool, Error> {
        let url = self.url.join("auth/check")?;
        let query_params = sign(
            app_key,
            &url,
            Method::GET,
            None,
            Utc::now() + Duration::from_secs(60),
        );
        let resp = self
            .client
            .get(url)
            .timeout(DEFAULT_API_TIMEOUT)
            .query(&query_params)
            .send()
            .await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::NO_CONTENT => Ok(true),
            _ => Err(Error::Api(resp.status(), resp.text().await?)),
        }
    }

    /// Requests an application connection to the indexer.
    pub(crate) async fn request_app_connection(
        &self,
        ephemeral_key: &PrivateKey,
        opts: &AppMetadata,
    ) -> Result<RegisterAppResponse, Error> {
        self.post_json("auth/connect", ephemeral_key, Some(opts))
            .await
    }

    /// Requests an application connection using a pre-authorized key, bypassing
    /// the interactive approval flow.
    pub(crate) async fn request_app_connection_pre_authorized(
        &self,
        ephemeral_key: &PrivateKey,
        opts: &AppMetadata,
        pre_authorized_key: &PrivateKey,
    ) -> Result<RegisterAppResponse, Error> {
        let public_key = pre_authorized_key.public_key();
        let sig_hash = pre_authorization_sig_hash(&ephemeral_key.public_key(), opts, &public_key);
        let request = AppConnectRequest {
            metadata: opts,
            pre_authorized_key: public_key,
            pre_authorization_signature: pre_authorized_key.sign(sig_hash.as_ref()),
        };
        self.post_json("auth/connect", ephemeral_key, Some(&request))
            .await
    }

    /// Checks if an auth request has been approved. Returns None if the
    /// request is still pending.
    pub(crate) async fn check_request_status(
        &self,
        ephemeral_key: &PrivateKey,
        status_url: Url,
    ) -> Result<Option<AuthApproval>, Error> {
        let query_params = sign(
            ephemeral_key,
            &status_url,
            Method::GET,
            None,
            Utc::now() + Duration::from_secs(60),
        );

        let resp = self
            .client
            .get(status_url)
            .timeout(DEFAULT_API_TIMEOUT)
            .query(&query_params)
            .send()
            .await?;
        let http_status = resp.status();
        match http_status {
            StatusCode::OK => {
                let status = Self::handle_response::<AuthConnectStatusResponse>(resp).await?;
                if !status.approved {
                    return Ok(None);
                }
                Ok(status.user_secret.map(|user_secret| AuthApproval {
                    user_secret,
                    reconnecting: status.reconnecting,
                }))
            }
            StatusCode::NOT_FOUND => Err(Error::UserRejected),
            _ => Err(Error::Api(http_status, resp.text().await?)),
        }
    }

    /// Registers the application key with the indexer.
    pub(crate) async fn register_app(
        &self,
        signing_key: &PrivateKey,
        app_key: &PrivateKey,
        register_url: Url,
    ) -> Result<(), Error> {
        let segments = register_url
            .path_segments()
            .ok_or(Error::Format("invalid register url format".into()))?;
        // ../auth/connect/:request_id/register
        let request_id = segments
            .rev()
            .nth(1)
            .ok_or(Error::Format("invalid register url format".into()))?;

        let sig_hash = register_app_sig_hash(request_id, &signing_key.public_key());
        let body = RegisterAppRequest {
            app_key: app_key.public_key(),
            signature: app_key.sign(sig_hash.as_ref()),
        };
        post_json::<_, EmptyResponse>(&self.client, register_url, signing_key, Some(&body))
            .await
            .map(|_| ())
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
        self.get_list("hosts", app_key, Some(&query)).await
    }

    /// Retrieves an object from the indexer by its key.
    pub(crate) async fn object(
        &self,
        app_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<SealedObject, Error> {
        self.get_json::<_, ()>(&format!("objects/{key}"), app_key, None)
            .await
    }

    /// Fetches a list of objects from the indexer. Can be paginated using the
    /// cursor and limit arguments.
    pub(crate) async fn objects(
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
        self.get_list("objects", app_key, Some(&query_params)).await
    }

    /// Pins an object to the indexer. If an object with the same ID already
    /// exists for the account, it is overwritten.
    pub(crate) async fn pin_object(
        &self,
        app_key: &PrivateKey,
        object: &SealedObject,
    ) -> Result<(), PinObjectError> {
        let req = PinObjectRequest::from(object);
        self.post_json::<_, EmptyResponse>("objects", app_key, Some(&req))
            .await
            .map(|_| ())
            .map_err(|e| match &e {
                Error::Api(_, message) if message.contains(ERROR_OBJECT_UNPINNED_SLAB) => {
                    PinObjectError::UnpinnedSlab
                }
                _ => PinObjectError::Client(e),
            })
    }

    /// Deletes an object from the indexer by its key.
    pub(crate) async fn delete_object(
        &self,
        app_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<(), Error> {
        self.delete(&format!("objects/{key}"), app_key).await
    }

    /// Pins slabs to the indexer.
    pub(crate) async fn pin_slabs(
        &self,
        app_key: &PrivateKey,
        slabs: &[SlabPinParams],
    ) -> Result<Vec<Hash256>, Error> {
        // indexd encodes an empty list as null
        self.post_json("slabs", app_key, Some(&slabs))
            .await
            .map(Option::unwrap_or_default)
    }

    /// Unpins slabs not used by any object on the account.
    ///
    /// `before` prunes only slabs pinned before that time. Without it the
    /// indexer applies its own cutoff.
    pub(crate) async fn prune_slabs(
        &self,
        app_key: &PrivateKey,
        before: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        let mut url = self.url.join("slabs/prune")?;
        if let Some(before) = before {
            url.query_pairs_mut()
                .append_pair("before", &before.to_rfc3339()); // indexd expects RFC3339
        }
        post_json::<(), EmptyResponse>(&self.client, url, app_key, None)
            .await
            .map(|_| ())
    }

    /// Account returns the current account.
    pub(crate) async fn account(&self, app_key: &PrivateKey) -> Result<Account, Error> {
        self.get_json::<_, ()>("account", app_key, None).await
    }

    /// Helper to send a signed DELETE request.
    async fn delete(&self, path: &str, app_key: &PrivateKey) -> Result<(), Error> {
        let url = self.url.join(path)?;
        delete(&self.client, url, app_key).await
    }

    /// Helper to send a signed GET request and parse the JSON or CBOR
    /// response.
    async fn get_json<D: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        path: &str,
        signing_key: &PrivateKey,
        query_params: Option<&Q>,
    ) -> Result<D, Error> {
        let url = self.url.join(path)?;
        get_json(&self.client, url, signing_key, query_params).await
    }

    /// Helper to send a signed GET request to a list endpoint. indexd encodes
    /// empty lists as null in both JSON and CBOR, so null decodes as an empty
    /// list.
    async fn get_list<T: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        path: &str,
        signing_key: &PrivateKey,
        query_params: Option<&Q>,
    ) -> Result<Vec<T>, Error> {
        self.get_json(path, signing_key, query_params)
            .await
            .map(Option::unwrap_or_default)
    }

    /// Helper to either parse a successful response according to its content
    /// type, falling back to JSON, or return the error message from the API.
    async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, Error> {
        if !resp.status().is_success() {
            return Err(Error::Api(resp.status(), resp.text().await?));
        }
        let is_cbor = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/cbor"));
        let body = resp.bytes().await?;
        if !is_cbor {
            return Ok(serde_json::from_slice(&body)?);
        }
        let mut rd = body.as_ref();
        let v = ciborium::from_reader(&mut rd)?;
        if !rd.is_empty() {
            return Err(ciborium::de::Error::Semantic(None, "trailing data".into()).into());
        }
        Ok(v)
    }

    /// Helper to send a signed POST request with a JSON body and parse the
    /// JSON or CBOR response.
    async fn post_json<S: Serialize, D: DeserializeOwned>(
        &self,
        path: &str,
        signing_key: &PrivateKey,
        body: Option<&S>,
    ) -> Result<D, Error> {
        let url = self.url.join(path)?;
        post_json(&self.client, url, signing_key, body).await
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
        // the Url crate does not allow "unsafe" scheme changes (https -> sia) because it's annoying.
        let mut url: Url = format!(
            "{SHARE_URL_SCHEME}://{}/objects/{}/shared",
            self.url.authority(),
            object.id()
        )
        .parse()?;

        let params = sign(app_key, &url, Method::GET, None, valid_until);
        url.set_fragment(Some(
            format!(
                "encryption_key={}",
                URL_SAFE.encode(object.data_key.as_ref())
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
    /// The metadata needed to download the data
    pub(crate) async fn shared_object(&self, mut share_url: Url) -> Result<Object, Error> {
        if share_url.scheme() != SHARE_URL_SCHEME {
            return Err(Error::Format(format!(
                "invalid url scheme: expected {SHARE_URL_SCHEME}"
            )));
        }
        let data_key = match share_url.fragment() {
            Some(fragment) => {
                let fragment = match fragment.strip_prefix("encryption_key=") {
                    Some(fragment) => Ok(fragment),
                    None => Err(Error::Format("missing encryption_key".into())),
                }?;
                // decode_slice writes only n bytes into out; require a full 32
                let mut out = [0u8; 32];
                match URL_SAFE.decode_slice(fragment, &mut out) {
                    Ok(32) => Ok(EncryptionKey::from(out)),
                    _ => Err(Error::Format(
                        "encryption key must be 32 bytes, base64url-encoded".into(),
                    )),
                }
            }
            None => Err(Error::Format("missing encryption_key".into())),
        }?;
        share_url.set_fragment(None);
        // enforce indexer App APIs are served over https
        // the Url crate does not allow "unsafe" scheme changes (sia -> https) because it's annoying.
        let share_url: Url = format!(
            "{SHARE_URL_FETCH_SCHEME}://{}",
            share_url.as_str().strip_prefix("sia://").unwrap()
        )
        .parse()?;
        let shared_object: SharedObjectResponse = Self::handle_response(
            self.client
                .get(share_url)
                .timeout(DEFAULT_API_TIMEOUT)
                .send()
                .await?,
        )
        .await?;

        Ok(Object {
            data_key,
            slabs: shared_object.slabs,
            ..Default::default()
        })
    }

    /// Fetches the sharing key's stats from the indexer.
    pub(crate) async fn shared_stats(&self, sharing_key: &PrivateKey) -> Result<KeyStats, Error> {
        self.get_json::<_, ()>("shared", sharing_key, None).await
    }

    /// Builds the offset and limit query params for a paginated request,
    /// omitting either that is not set.
    fn pagination_query(offset: Option<u64>, limit: Option<u64>) -> Vec<(&'static str, String)> {
        let mut query = Vec::new();
        if let Some(offset) = offset {
            query.push(("offset", offset.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        query
    }

    /// Lists the objects the sharing key grants access to.
    pub(crate) async fn shared_objects(
        &self,
        sharing_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<SealedObject>, Error> {
        let query = Self::pagination_query(offset, limit);
        self.get_list("shared/objects", sharing_key, Some(&query))
            .await
    }

    /// Lists the objects the sharing key grants access to without their
    /// slabs.
    pub(crate) async fn shared_object_summaries(
        &self,
        sharing_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<SealedObjectSummary>, Error> {
        let mut query = Self::pagination_query(offset, limit);
        query.push(("includeslabs", "false".to_string()));
        self.get_list("shared/objects", sharing_key, Some(&query))
            .await
    }

    /// Retrieves a single object the sharing key grants access to.
    pub(crate) async fn shared_object_by_id(
        &self,
        sharing_key: &PrivateKey,
        key: &Hash256,
    ) -> Result<SealedObject, Error> {
        self.get_json::<_, ()>(&format!("shared/objects/{key}"), sharing_key, None)
            .await
    }

    /// Lists usable hosts, each paired with an account token the recipient uses
    /// to pay for downloads from it.
    pub(crate) async fn shared_hosts(
        &self,
        sharing_key: &PrivateKey,
        query: HostQuery,
    ) -> Result<Vec<SharedHost>, Error> {
        self.get_list("shared/hosts", sharing_key, Some(&query))
            .await
    }

    /// Creates a sharing key for the account.
    pub(crate) async fn add_sharing_key(
        &self,
        app_key: &PrivateKey,
        req: &KeyRequest,
    ) -> Result<KeyResponse, Error> {
        self.post_json("sharing", app_key, Some(req)).await
    }

    /// Lists the account's sharing keys.
    pub(crate) async fn sharing_keys(
        &self,
        app_key: &PrivateKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<KeyResponse>, Error> {
        let query = Self::pagination_query(offset, limit);
        self.get_list("sharing", app_key, Some(&query)).await
    }

    /// Retrieves one of the account's sharing keys by its public key.
    pub(crate) async fn sharing_key(
        &self,
        app_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<KeyResponse, Error> {
        self.get_json::<_, ()>(&format!("sharing/{public_key}"), app_key, None)
            .await
    }

    /// Deletes one of the account's sharing keys.
    pub(crate) async fn delete_sharing_key(
        &self,
        app_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        self.delete(&format!("sharing/{public_key}"), app_key).await
    }

    /// Attaches an object the account owns to one of its sharing keys.
    pub(crate) async fn add_shared_object(
        &self,
        app_key: &PrivateKey,
        sharing_key: &PublicKey,
        req: &SharedObjectRequest,
    ) -> Result<(), Error> {
        self.post_json::<_, EmptyResponse>(
            &format!("sharing/{sharing_key}/objects"),
            app_key,
            Some(req),
        )
        .await
        .map(|_| ())
    }

    /// Lists the objects attached to one of the account's sharing keys.
    pub(crate) async fn sharing_key_objects(
        &self,
        app_key: &PrivateKey,
        sharing_key: &PublicKey,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<SealedObject>, Error> {
        let query = Self::pagination_query(offset, limit);
        self.get_list(
            &format!("sharing/{sharing_key}/objects"),
            app_key,
            Some(&query),
        )
        .await
    }

    /// Detaches an object from one of the account's sharing keys.
    pub(crate) async fn delete_shared_object(
        &self,
        app_key: &PrivateKey,
        sharing_key: &PublicKey,
        object_key: &Hash256,
    ) -> Result<(), Error> {
        self.delete(
            &format!("sharing/{sharing_key}/objects/{object_key}"),
            app_key,
        )
        .await
    }
}

fn http_client(cbor: bool) -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(if cbor { ACCEPT_CBOR } else { ACCEPT_JSON }),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("http client configuration is valid")
}

async fn get_json<D: DeserializeOwned, Q: Serialize + ?Sized>(
    client: &reqwest::Client,
    url: Url,
    signing_key: &PrivateKey,
    query_params: Option<&Q>,
) -> Result<D, Error> {
    let signing_params = sign(
        signing_key,
        &url,
        Method::GET,
        None,
        Utc::now() + Duration::from_secs(60),
    );

    let mut builder = client
        .get(url)
        .timeout(DEFAULT_API_TIMEOUT)
        .query(&signing_params);
    if let Some(q) = query_params {
        builder = builder.query(q);
    }
    Client::handle_response(builder.send().await?).await
}

async fn post_json<S: Serialize, D: DeserializeOwned>(
    client: &reqwest::Client,
    url: Url,
    signing_key: &PrivateKey,
    body: Option<&S>,
) -> Result<D, Error> {
    let body = body.and_then(|body| to_vec(body).ok());
    let params = &sign(
        signing_key,
        &url,
        Method::POST,
        body.as_deref(),
        Utc::now() + Duration::from_secs(60),
    );
    let mut builder = client.post(url).timeout(DEFAULT_API_TIMEOUT).query(params);
    if let Some(body) = body {
        builder = builder.body(body);
    }
    Client::handle_response(builder.send().await?).await
}

async fn delete(client: &reqwest::Client, url: Url, app_key: &PrivateKey) -> Result<(), Error> {
    let query_params = sign(
        app_key,
        &url,
        Method::DELETE,
        None,
        Utc::now() + Duration::from_secs(60),
    );
    Client::handle_response::<EmptyResponse>(
        client
            .delete(url)
            .timeout(DEFAULT_API_TIMEOUT)
            .query(&query_params)
            .send()
            .await?,
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod test {
    use sia_core::rhp4::AccountToken;

    use super::*;

    #[sia_core_derive::cross_target_test]
    fn test_pagination_query() {
        assert!(Client::pagination_query(None, None).is_empty());
        assert_eq!(
            Client::pagination_query(Some(5), None),
            vec![("offset", "5".to_string())]
        );
        assert_eq!(
            Client::pagination_query(None, Some(10)),
            vec![("limit", "10".to_string())]
        );
        assert_eq!(
            Client::pagination_query(Some(5), Some(10)),
            vec![("offset", "5".to_string()), ("limit", "10".to_string())]
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_key_stats_deserializes_go_wire_format() {
        // A literal body pins the wire format (Go's camelCase JSON tags) rather
        // than round-tripping our own struct.
        const KEY_STATS_JSON: &str = r#"{
            "objectCount": 3,
            "objectSize": 1024,
            "pinnedData": 2048,
            "pinnedSize": 6144,
            "expiresAt": "2027-01-02T03:04:05Z",
            "createdAt": "2026-01-02T03:04:05Z",
            "updatedAt": "2026-02-02T03:04:05Z"
        }"#;

        assert_eq!(
            serde_json::from_str::<KeyStats>(KEY_STATS_JSON).unwrap(),
            KeyStats {
                object_count: 3,
                object_size: 1024,
                pinned_data: 2048,
                pinned_size: 6144,
                expires_at: Some("2027-01-02T03:04:05Z".parse().unwrap()),
                created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
                updated_at: "2026-02-02T03:04:05Z".parse().unwrap(),
            }
        );
    }

    #[sia_core_derive::cross_target_test]
    fn test_shared_host_flattens_host_fields() {
        let shared_host = SharedHost {
            host: Host {
                public_key: PublicKey::new([4u8; 32]),
                addresses: vec![],
                country_code: "US".to_string(),
                latitude: 1.5,
                longitude: 2.5,
                good_for_upload: true,
            },
            token: AccountToken::new(
                &PrivateKey::from_seed(&[5u8; 32]),
                PublicKey::new([4u8; 32]),
            ),
        };

        // The host fields must flatten to the top level, matching Go's embedded
        // HostInfo, not nest under a "host" key.
        let json = serde_json::to_value(&shared_host).unwrap();
        assert!(json.get("publicKey").is_some(), "host fields not flattened");
        assert!(json.get("host").is_none(), "host fields wrongly nested");
        assert!(json.get("token").is_some());
    }
}

/// Integration tests requiring httptest, a native TCP mock server. Native only.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod native_tests {
    use base64::engine::general_purpose::URL_SAFE;
    use chrono::FixedOffset;
    use sia_core::rhp4::AccountToken;
    use sia_core::signing::{PublicKey, Signature};
    use sia_core::{hash_256, public_key};

    use crate::AppKey;
    use crate::sharing::Nonce;

    use crate::app_client::cross_target_test::{ACCOUNT_CBOR, STATUS_CBOR};
    use crate::app_client::{
        QUERY_PARAM_CREDENTIAL, QUERY_PARAM_SIGNATURE, QUERY_PARAM_VALID_UNTIL, SectorPinParams,
        request_hash,
    };
    use crate::slabs::SlabVersion::V0;
    use crate::{AppID, GeoLocation, Protocol, Sector, Slab};

    use super::*;
    use httptest::http::Response;
    use httptest::matchers::*;
    use httptest::{Expectation, Server};

    #[tokio::test]
    async fn test_handle_response_content_type() {
        let cbor = hex::decode(ACCOUNT_CBOR).unwrap();
        let expected: Account = ciborium::from_reader(cbor.as_slice()).unwrap();
        let json = serde_json::to_vec(&expected).unwrap();

        for (cbor_enabled, accept) in [(true, ACCEPT_CBOR), (false, ACCEPT_JSON)] {
            for (content_type, body) in [
                (None, json.clone()),
                (Some("application/json"), json.clone()),
                (Some("application/cbor; charset=binary"), cbor.clone()),
            ] {
                let server = Server::run();
                let mut response = Response::builder().status(StatusCode::OK);
                if let Some(content_type) = content_type {
                    response = response.header("content-type", content_type);
                }
                server.expect(
                    Expectation::matching(all_of![
                        request::method_path("GET", "/account"),
                        request::headers(contains(("accept", accept))),
                    ])
                    .respond_with(response.body(body).unwrap()),
                );

                let app_key = PrivateKey::from_seed(&rand::random());
                let mut client = Client::new(server.url("/").to_string()).unwrap();
                client.set_cbor(cbor_enabled);
                let account = client
                    .account(&app_key)
                    .await
                    .unwrap_or_else(|e| panic!("{accept} {content_type:?}: {e}"));
                assert_eq!(account, expected, "{accept} {content_type:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_handle_response_malformed_cbor() {
        // 0xff is a "break" with no indefinite-length item to end. 0xf6 is a
        // valid null, so the second body has trailing data.
        for body in [vec![0xff], vec![0xf6, 0xff]] {
            let server = Server::run();
            server.expect(
                Expectation::matching(request::path("/slabs"))
                    .respond_with(ok_typed("application/cbor", body.clone())),
            );

            let app_key = PrivateKey::from_seed(&rand::random());
            let client = Client::new(server.url("/").to_string()).unwrap();
            let err = client.pin_slabs(&app_key, &[]).await.unwrap_err();
            assert!(matches!(err, Error::Cbor(_)), "{body:x?}: {err}");
            assert!(err.is_retryable());
        }
    }

    #[tokio::test]
    async fn test_list_endpoints_null() {
        // `null` in each response encoding; 0xf6 is CBOR's null
        for (content_type, body) in [
            ("application/json", &b"null"[..]),
            ("application/cbor", &[0xf6]),
        ] {
            let server = Server::run();
            for (method, path) in [("GET", "/hosts"), ("POST", "/slabs")] {
                server.expect(
                    Expectation::matching(request::method_path(method, path))
                        .respond_with(ok_typed(content_type, body)),
                );
            }

            let app_key = PrivateKey::from_seed(&rand::random());
            let client = Client::new(server.url("/").to_string()).unwrap();
            let hosts = client
                .hosts(&app_key, HostQuery::default())
                .await
                .unwrap_or_else(|e| panic!("{content_type}: {e}"));
            assert!(hosts.is_empty(), "{content_type}");
            let slab_ids = client
                .pin_slabs(&app_key, &[])
                .await
                .unwrap_or_else(|e| panic!("{content_type}: {e}"));
            assert!(slab_ids.is_empty(), "{content_type}");
        }
    }

    /// Validates a signed HTTP request by reconstructing the URL from the
    /// request, then verifying the credential, signature, and expiration.
    /// Panics if the signature is invalid.
    fn validate_url_signature_request(
        req: &httptest::http::Request<httptest::bytes::Bytes>,
    ) -> PublicKey {
        let host = req
            .headers()
            .get("host")
            .expect("missing host header")
            .to_str()
            .expect("invalid host header");
        let uri = req.uri();
        let url: Url = format!("http://{}{}", host, uri)
            .parse()
            .expect("invalid url");
        let method: Method = req.method().clone();
        let body = req.body();
        let body = if body.is_empty() {
            None
        } else {
            Some(body.as_ref())
        };

        let query_pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();

        let credential_str = query_pairs
            .get(QUERY_PARAM_CREDENTIAL)
            .unwrap_or_else(|| panic!("missing {QUERY_PARAM_CREDENTIAL} parameter"));
        let signature_str = query_pairs
            .get(QUERY_PARAM_SIGNATURE)
            .unwrap_or_else(|| panic!("missing {QUERY_PARAM_SIGNATURE} parameter"));
        let valid_until_str = query_pairs
            .get(QUERY_PARAM_VALID_UNTIL)
            .unwrap_or_else(|| panic!("missing {QUERY_PARAM_VALID_UNTIL} parameter"));

        // parse credential (public key)
        let mut pk_bytes = [0u8; 32];
        let n = URL_SAFE
            .decode_slice(credential_str.as_bytes(), &mut pk_bytes)
            .expect("invalid credential encoding");
        assert_eq!(n, 32, "invalid credential length");
        let pk = PublicKey::new(pk_bytes);

        // parse signature
        let mut sig_bytes = [0u8; 64];
        let n = URL_SAFE
            .decode_slice(signature_str.as_bytes(), &mut sig_bytes)
            .expect("invalid signature encoding");
        assert_eq!(n, 64, "invalid signature length");
        let sig = Signature::from(sig_bytes);

        // parse valid_until
        let ts: i64 = valid_until_str.parse().expect("invalid timestamp");
        let valid_until = DateTime::from_timestamp(ts, 0).expect("invalid timestamp");

        assert!(valid_until >= Utc::now(), "signature expired");

        // strip the auth query params to compute the hash over the original URL
        let mut verify_url = url.clone();
        {
            let filtered: Vec<(String, String)> = verify_url
                .query_pairs()
                .filter(|(k, _)| {
                    k != QUERY_PARAM_CREDENTIAL
                        && k != QUERY_PARAM_SIGNATURE
                        && k != QUERY_PARAM_VALID_UNTIL
                })
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            if filtered.is_empty() {
                verify_url.set_query(None);
            } else {
                verify_url.query_pairs_mut().clear().extend_pairs(&filtered);
            }
        }

        let hash = request_hash(&verify_url, method, body, valid_until);
        assert!(pk.verify(hash.as_ref(), &sig), "invalid signature");
        pk
    }

    #[tokio::test]
    async fn test_shared_object_roundtrip() {
        let data_key: EncryptionKey = [42u8; 32].into();
        let slabs = vec![Slab {
            version: V0,
            encryption_key: [1u8; 32].into(),
            min_shards: 1,
            sectors: vec![Sector {
                root: Hash256::new([2u8; 32]),
                host_key: PublicKey::new([3u8; 32]),
            }],
            offset: 0,
            length: 256,
        }];
        let object = Object {
            data_key: data_key.clone(),
            slabs: slabs.clone(),
            ..Default::default()
        };
        let object_id = object.id();

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/objects/{object_id}/shared"),
            ))
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(
                        serde_json::to_string(&SharedObjectResponse {
                            slabs: slabs.clone(),
                            encrypted_metadata: None,
                        })
                        .unwrap(),
                    )
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&[0u8; 32]);
        let client = Client::new(server.url("/").to_string()).unwrap();
        let valid_until = DateTime::from_timestamp_secs(123).unwrap() + Duration::from_secs(60);
        let share_url = client
            .shared_object_url(&app_key, &object, valid_until)
            .unwrap();

        assert_eq!(share_url.scheme(), SHARE_URL_SCHEME);
        assert_eq!(share_url.path(), format!("/objects/{object_id}/shared"));

        // ensure it returns an error if the scheme is wrong
        let invalid_url: Url = share_url
            .clone()
            .as_str()
            .replace("sia://", "http://")
            .parse()
            .unwrap();
        assert!(client.shared_object(invalid_url).await.is_err());

        let result = client.shared_object(share_url).await.unwrap();
        assert_eq!(&result.data_key, &data_key);
        assert_eq!(result.slabs(), &slabs);
    }

    #[tokio::test]
    async fn test_signed_auth() {
        let app_key = PrivateKey::from_seed(&rand::random());
        let expected_pk = app_key.public_key();

        let server = Server::run();
        server.expect(
            Expectation::matching(
                move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                    let pk = validate_url_signature_request(req);
                    pk == expected_pk
                },
            )
            .times(5)
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let client = Client::new(server.url("/").to_string()).unwrap();
        client
            .get_json::<EmptyResponse, ()>("", &app_key, None)
            .await
            .expect("GET request failed");
        client
            .get_json::<EmptyResponse, _>("", &app_key, Some(&[("foo", "bar"), ("baz", "1")]))
            .await
            .expect("GET with query params failed");
        client
            .post_json::<[u8; 3], EmptyResponse>("", &app_key, Some(&[1u8, 2, 3]))
            .await
            .expect("POST with body failed");
        client
            .post_json::<(), EmptyResponse>("", &app_key, None)
            .await
            .expect("POST request failed");
        client
            .delete("", &app_key)
            .await
            .expect("DELETE request failed");
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
    async fn test_requests_compression() {
        // `[]` encoded with each supported content encoding
        const EMPTY_LISTS: &[(&str, &[u8])] = &[
            (
                "gzip",
                &[
                    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8b, 0x8e, 0x05,
                    0x00, 0x29, 0xbb, 0x4c, 0x0d, 0x02, 0x00, 0x00, 0x00,
                ],
            ),
            (
                "zstd",
                &[
                    0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x11, 0x00, 0x00, 0x5b, 0x5d, 0x56, 0x1f,
                    0x7f, 0x61,
                ],
            ),
        ];

        for (encoding, body) in EMPTY_LISTS {
            let server = Server::run();
            server.expect(
                Expectation::matching(all_of![
                    request::method_path("GET", "/hosts"),
                    request::headers(contains((
                        "accept-encoding",
                        all_of![matches(r"\bgzip\b"), matches(r"\bzstd\b")]
                    ))),
                ])
                .respond_with(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-encoding", *encoding)
                        .body(body.to_vec())
                        .unwrap(),
                ),
            );

            let app_key = PrivateKey::from_seed(&rand::random());
            let client = Client::new(server.url("/").to_string()).unwrap();
            let hosts = client
                .hosts(&app_key, HostQuery::default())
                .await
                .unwrap_or_else(|e| panic!("{encoding}: {e}"));
            assert!(hosts.is_empty(), "{encoding}");
        }
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
    async fn test_pin_slabs_upload_times() {
        let params = SlabPinParams {
            version: V0,
            encryption_key: [1u8; 32].into(),
            min_shards: 1,
            sectors: vec![
                SectorPinParams {
                    sector: Sector {
                        root: hash_256!(
                            "826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6"
                        ),
                        host_key: public_key!(
                            "ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe"
                        ),
                    },
                    uploaded_at: Some(
                        DateTime::<FixedOffset>::parse_from_rfc3339("2026-10-02T10:00:00Z")
                            .unwrap()
                            .to_utc(),
                    ),
                },
                SectorPinParams {
                    sector: Sector {
                        root: hash_256!(
                            "3017354ace367561d4c568263463c17d3c16030c637734e12e9418be1f2f8e65"
                        ),
                        host_key: public_key!(
                            "ed25519:9f5fb0b962f29497b3993e12c7a7880fbaf0cf52bad3620af0280895fdea8ece"
                        ),
                    },
                    uploaded_at: None,
                },
            ],
        };

        // A sector without an upload time, as when re-pinning an existing
        // slab, omits the field rather than sending null.
        const EXPECTED_JSON: &str = r#"
        [
          {
            "version": 0,
            "encryptionKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "minShards": 1,
            "sectors": [
              {
                "root": "826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6",
                "hostKey": "ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe",
                "uploadedAt": "2026-10-02T10:00:00Z"
              },
              {
                "root": "3017354ace367561d4c568263463c17d3c16030c637734e12e9418be1f2f8e65",
                "hostKey": "ed25519:9f5fb0b962f29497b3993e12c7a7880fbaf0cf52bad3620af0280895fdea8ece"
              }
            ]
          }
        ]
        "#;
        let expected: serde_json::Value = serde_json::from_str(EXPECTED_JSON).unwrap();
        let slab_id = hash_256!("43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28");

        let server = Server::run();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/slabs"),
                request::body(json_decoded(eq(expected))),
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(format!(r#"["{slab_id}"]"#))
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        assert_eq!(
            client.pin_slabs(&app_key, &[params]).await.unwrap(),
            [slab_id]
        );
    }

    #[tokio::test]
    async fn test_pin_slabs_upload_too_old() {
        let message = "invalid slab pin params: slab 0: sector 3 invalid: slab upload is too old (max 48h0m0s)";
        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path("POST", "/slabs")).respond_with(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(message)
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        let error = client.pin_slabs(&app_key, &[]).await.unwrap_err();
        assert!(error.is_slab_upload_too_old());
        assert!(!error.is_retryable());
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
        client.prune_slabs(&app_key, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_prune_slabs_before() {
        let server = Server::run();

        // The cutoff has to reach indexd as RFC3339, and the signature covers
        // the path only, so adding it to the query does not disturb auth.
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/slabs/prune"),
                request::query(url_decoded(contains((
                    "before",
                    "2025-09-09T23:10:46.898399+00:00"
                )))),
            ])
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let before = DateTime::parse_from_rfc3339("2025-09-09T16:10:46.898399-07:00")
            .unwrap()
            .with_timezone(&Utc);
        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        client.prune_slabs(&app_key, Some(before)).await.unwrap();
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

        let expected_error = Error::Api(
            StatusCode::INTERNAL_SERVER_ERROR,
            "something went wrong".to_string(),
        );
        let get_error = client
            .get_json::<(), ()>("", &app_key, None)
            .await
            .unwrap_err();
        assert_eq!(get_error.to_string(), expected_error.to_string());
        let post_error = client
            .post_json::<(), ()>("", &app_key, None)
            .await
            .unwrap_err();
        assert_eq!(post_error.to_string(), expected_error.to_string());
        let delete_error = client.delete("", &app_key).await.unwrap_err();
        assert_eq!(delete_error.to_string(), expected_error.to_string());
    }

    #[tokio::test]
    async fn test_handle_response_typed_statuses() {
        let server = Server::run();
        for (path, status) in [
            ("/missing", StatusCode::NOT_FOUND),
            ("/denied", StatusCode::UNAUTHORIZED),
            ("/invalid", StatusCode::BAD_REQUEST),
            ("/broken", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            server.expect(
                Expectation::matching(request::path(path))
                    .times(1)
                    .respond_with(Response::builder().status(status).body("the body").unwrap()),
            );
        }

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();

        let not_found = client.delete("missing", &app_key).await.unwrap_err();
        assert!(matches!(not_found, Error::Api(StatusCode::NOT_FOUND, ref m) if m == "the body"));
        let denied = client.delete("denied", &app_key).await.unwrap_err();
        assert!(matches!(denied, Error::Api(StatusCode::UNAUTHORIZED, ref m) if m == "the body"));
        let invalid = client.delete("invalid", &app_key).await.unwrap_err();
        assert!(matches!(invalid, Error::Api(StatusCode::BAD_REQUEST, ref m) if m == "the body"));
        let other = client.delete("broken", &app_key).await.unwrap_err();
        assert!(
            matches!(other, Error::Api(StatusCode::INTERNAL_SERVER_ERROR, ref m) if m == "the body")
        );

        // 404 and 401 cannot become a success on retry. Neither can a 400
        // without changing the request. Transient failures may.
        assert!(!not_found.is_retryable());
        assert!(!denied.is_retryable());
        assert!(!invalid.is_retryable());
        assert!(other.is_retryable());
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
            Expectation::matching(request::method_path("GET", "/reconnecting")).respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("{\"approved\": true, \"reconnecting\": true, \"userSecret\": \"3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2\"}")
                    .unwrap(),
            ),
        );
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/cbor"),
                request::headers(contains(("accept", ACCEPT_CBOR))),
            ])
            .respond_with(ok_typed(
                "application/cbor",
                hex::decode(STATUS_CBOR).unwrap(),
            )),
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
        let ephemeral_key = PrivateKey::from_seed(&rand::random());

        // approved request, from an indexer that does not report reconnecting
        let status_url: Url = server.url("/approved").to_string().parse().unwrap();
        assert_eq!(
            client
                .check_request_status(&ephemeral_key, status_url)
                .await
                .unwrap()
                .unwrap(),
            AuthApproval {
                user_secret: hash_256!(
                    "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2"
                ),
                reconnecting: false,
            }
        );

        // approved request, from a returning user
        let status_url: Url = server.url("/reconnecting").to_string().parse().unwrap();
        assert_eq!(
            client
                .check_request_status(&ephemeral_key, status_url)
                .await
                .unwrap()
                .unwrap(),
            AuthApproval {
                user_secret: hash_256!(
                    "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2"
                ),
                reconnecting: true,
            }
        );

        // approved request, CBOR-encoded
        let status_url: Url = server.url("/cbor").to_string().parse().unwrap();
        assert_eq!(
            client
                .check_request_status(&ephemeral_key, status_url)
                .await
                .unwrap()
                .unwrap(),
            AuthApproval {
                user_secret: hash_256!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                ),
                reconnecting: true,
            }
        );

        // rejected request
        let status_url: Url = server.url("/rejected").to_string().parse().unwrap();
        assert!(matches!(
            client
                .check_request_status(&ephemeral_key, status_url)
                .await
                .unwrap_err(),
            Error::UserRejected,
        ));

        // other error
        let status_url: Url = server.url("/error").to_string().parse().unwrap();
        let err = client
            .check_request_status(&ephemeral_key, status_url)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "indexd responded with an error: 500 Internal Server Error: something went wrong"
        );
    }

    #[tokio::test]
    async fn test_check_app_auth() {
        let server = Server::run();
        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();

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
            "indexd responded with an error: 500 Internal Server Error: something went wrong"
        );
    }

    #[tokio::test]
    async fn test_request_app_connection() {
        let server = Server::run();
        let app_id = AppID::from(rand::random::<[u8; 32]>());
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/auth/connect"),
                request::body(format!(r#"{{"appID":"{app_id}","name":"name","description":"description","serviceURL":"https://service.com","logoURL":"https://logo.com","callbackURL":"https://callback.com"}}"#)),
            ])
                .respond_with(Response::builder().status(StatusCode::OK).body(r#"{"responseURL":"https://response.com", "registerURL":"https://response.com","statusURL":"https://status.com","expiration":"1970-01-01T01:01:40+01:00"}"#).unwrap()),
        );

        let client = Client::new(server.url("/").to_string()).unwrap();
        let ephemeral_key = PrivateKey::from_seed(&rand::random());
        let resp = client
            .request_app_connection(
                &ephemeral_key,
                &AppMetadata {
                    id: app_id,
                    name: "name",
                    description: "description",
                    service_url: "https://service.com",
                    logo_url: Some("https://logo.com"),
                    callback_url: Some("https://callback.com"),
                },
            )
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
                    version: V0,
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
                    version: V0,
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
                    version: V0,
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
                    version: V0,
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
                        after: object.updated_at,
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
    async fn test_pin_object() {
        let object = SealedObject {
            encrypted_data_key: vec![1u8; 72],
            encrypted_metadata_key: vec![1u8; 72],
            data_signature: Signature::from([2u8; 64]),
            metadata_signature: Signature::from([2u8; 64]),
            slabs: vec![
                Slab {
                    version: V0,
                    encryption_key: [1u8; 32].into(),
                    min_shards: 2,
                    sectors: vec![],
                    offset: 0,
                    length: 256,
                },
                Slab {
                    version: V0,
                    encryption_key: [2u8; 32].into(),
                    min_shards: 2,
                    sectors: vec![],
                    offset: 256,
                    length: 512,
                },
            ],
            encrypted_metadata: b"hello world!".to_vec(),
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

        let pin_request = PinObjectRequest::from(&object);

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/objects"),
                request::body(serde_json::to_string(&pin_request).unwrap())
            ])
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string()).unwrap();
        client.pin_object(&app_key, &object).await.unwrap();
    }

    #[tokio::test]
    async fn test_register_flow() {
        let ephemeral_key = PrivateKey::from_seed(&rand::random());
        let ephemeral_pk = ephemeral_key.public_key();
        let app_key = PrivateKey::from_seed(&rand::random());
        let app_pk = app_key.public_key();

        let app_id = AppID::from(rand::random::<[u8; 32]>());
        let metadata = AppMetadata {
            id: app_id,
            name: "test-app",
            description: "A test application",
            service_url: "https://test-app.com",
            logo_url: Some("https://test-app.com/logo.png"),
            callback_url: Some("https://test-app.com/callback"),
        };

        let server = Server::run();
        let request_id = "abc123def456";

        // step 1: request_app_connection — signed with ephemeral key, body has metadata
        let expected_body = serde_json::to_string(&metadata).unwrap();
        let step1_ephemeral_pk = ephemeral_pk;
        server.expect(
            Expectation::matching(move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                let pk = validate_url_signature_request(req);
                pk == step1_ephemeral_pk
                    && req.method() == "POST"
                    && req.uri().path() == "/auth/connect"
                    && req.body().as_ref() == expected_body.as_bytes()
            })
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(format!(
                        r#"{{"responseURL":"http://example.com/auth/connect/{request_id}","statusURL":"{}","registerURL":"{}","expiration":"2030-01-01T00:00:00Z"}}"#,
                        server.url(&format!("/auth/connect/{request_id}/status")),
                        server.url(&format!("/auth/connect/{request_id}/register"))
                    ))
                    .unwrap(),
            ),
        );

        // step 2: check_request_status — signed with ephemeral key
        let step2_ephemeral_pk = ephemeral_pk;
        let user_secret = Hash256::new(rand::random());
        let status_response = serde_json::to_string(&AuthConnectStatusResponse {
            approved: true,
            reconnecting: false,
            user_secret: Some(user_secret),
        })
        .unwrap();
        server.expect(
            Expectation::matching(
                move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                    let pk = validate_url_signature_request(req);
                    pk == step2_ephemeral_pk
                        && req.method() == "GET"
                        && req.uri().path() == format!("/auth/connect/{request_id}/status")
                },
            )
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(status_response)
                    .unwrap(),
            ),
        );

        // step 3: register_app — signed with ephemeral key, body has app key + valid signature
        let step3_ephemeral_pk = ephemeral_pk;
        let step3_app_pk = app_pk;
        server.expect(
            Expectation::matching(
                move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                    let pk = validate_url_signature_request(req);
                    if pk != step3_ephemeral_pk || req.method() != "POST" {
                        return false;
                    }
                    if req.uri().path() != format!("/auth/connect/{request_id}/register") {
                        return false;
                    }
                    // verify the body contains a valid RegisterAppRequest
                    let body: RegisterAppRequest =
                        serde_json::from_slice(req.body().as_ref()).expect("invalid body");
                    if body.app_key != step3_app_pk {
                        return false;
                    }
                    // verify the app key ownership signature
                    let sig_hash = register_app_sig_hash(request_id, &step3_ephemeral_pk);
                    step3_app_pk.verify(sig_hash.as_ref(), &body.signature)
                },
            )
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        // run the flow
        let client = Client::new(server.url("/").to_string()).unwrap();

        // step 1
        let resp = client
            .request_app_connection(&ephemeral_key, &metadata)
            .await
            .unwrap();

        // step 2
        let status_url: Url = resp.status_url.parse().unwrap();
        let approval = client
            .check_request_status(&ephemeral_key, status_url)
            .await
            .unwrap();
        assert_eq!(approval.map(|a| a.user_secret), Some(user_secret));

        // step 3
        let register_url: Url = resp.register_url.parse().unwrap();
        client
            .register_app(&ephemeral_key, &app_key, register_url)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_pre_authorized_connect_flow() {
        let ephemeral_key = PrivateKey::from_seed(&rand::random());
        let ephemeral_pk = ephemeral_key.public_key();
        let pre_auth_key = PrivateKey::from_seed(&rand::random());
        let pre_auth_pk = pre_auth_key.public_key();
        let app_key = PrivateKey::from_seed(&rand::random());
        let app_pk = app_key.public_key();

        let app_id = AppID::from(rand::random::<[u8; 32]>());
        let metadata = AppMetadata {
            id: app_id,
            name: "test-app",
            description: "A test application",
            service_url: "https://test-app.com",
            logo_url: Some("https://test-app.com/logo.png"),
            callback_url: Some("https://test-app.com/callback"),
        };

        // the exact hash the pre-authorized key must sign for this request
        let expected_sig_hash = pre_authorization_sig_hash(&ephemeral_pk, &metadata, &pre_auth_pk);

        let server = Server::run();
        let request_id = "preauth123";

        #[derive(serde::Deserialize)]
        struct PreAuthBody {
            #[serde(rename = "preAuthorizedKey")]
            pre_authorized_key: PublicKey,
            #[serde(rename = "preAuthorizationSignature")]
            pre_authorization_signature: Signature,
        }

        // step 1: the connect body must carry the pre-authorized public key and a
        // signature that verifies over the proof hash (i.e. the client signed the
        // right hash with the right key).
        let step1_ephemeral_pk = ephemeral_pk;
        let step1_pre_auth_pk = pre_auth_pk;
        server.expect(
            Expectation::matching(move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                let pk = validate_url_signature_request(req);
                if pk != step1_ephemeral_pk
                    || req.method() != "POST"
                    || req.uri().path() != "/auth/connect"
                {
                    return false;
                }
                let body: PreAuthBody =
                    serde_json::from_slice(req.body().as_ref()).expect("invalid body");
                body.pre_authorized_key == step1_pre_auth_pk
                    && step1_pre_auth_pk
                        .verify(expected_sig_hash.as_ref(), &body.pre_authorization_signature)
            })
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(format!(
                        r#"{{"responseURL":"http://example.com/auth/connect/{request_id}","statusURL":"{}","registerURL":"{}","expiration":"2030-01-01T00:00:00Z"}}"#,
                        server.url(&format!("/auth/connect/{request_id}/status")),
                        server.url(&format!("/auth/connect/{request_id}/register"))
                    ))
                    .unwrap(),
            ),
        );

        // step 2: a pre-authorized request is approved synchronously, so status
        // returns the user secret on the first check.
        let step2_ephemeral_pk = ephemeral_pk;
        let user_secret = Hash256::new(rand::random());
        let status_response = serde_json::to_string(&AuthConnectStatusResponse {
            approved: true,
            reconnecting: false,
            user_secret: Some(user_secret),
        })
        .unwrap();
        server.expect(
            Expectation::matching(
                move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                    let pk = validate_url_signature_request(req);
                    pk == step2_ephemeral_pk
                        && req.method() == "GET"
                        && req.uri().path() == format!("/auth/connect/{request_id}/status")
                },
            )
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(status_response)
                    .unwrap(),
            ),
        );

        // step 3: register the app key (identical to the interactive flow).
        let step3_ephemeral_pk = ephemeral_pk;
        let step3_app_pk = app_pk;
        server.expect(
            Expectation::matching(
                move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                    let pk = validate_url_signature_request(req);
                    if pk != step3_ephemeral_pk || req.method() != "POST" {
                        return false;
                    }
                    if req.uri().path() != format!("/auth/connect/{request_id}/register") {
                        return false;
                    }
                    let body: RegisterAppRequest =
                        serde_json::from_slice(req.body().as_ref()).expect("invalid body");
                    if body.app_key != step3_app_pk {
                        return false;
                    }
                    let sig_hash = register_app_sig_hash(request_id, &step3_ephemeral_pk);
                    step3_app_pk.verify(sig_hash.as_ref(), &body.signature)
                },
            )
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        // run the pre-authorized flow at the client level
        let client = Client::new(server.url("/").to_string()).unwrap();

        let resp = client
            .request_app_connection_pre_authorized(&ephemeral_key, &metadata, &pre_auth_key)
            .await
            .unwrap();

        let status_url: Url = resp.status_url.parse().unwrap();
        let approval = client
            .check_request_status(&ephemeral_key, status_url)
            .await
            .unwrap();
        assert_eq!(approval.map(|a| a.user_secret), Some(user_secret));

        let register_url: Url = resp.register_url.parse().unwrap();
        client
            .register_app(&ephemeral_key, &app_key, register_url)
            .await
            .unwrap();
    }

    /// Matches a GET to `path` whose url signature was made by `by`.
    fn signed_get(
        path: impl Into<String>,
        by: PublicKey,
    ) -> impl Fn(&httptest::http::Request<httptest::bytes::Bytes>) -> bool {
        let path = path.into();
        move |req| {
            req.method() == "GET"
                && req.uri().path() == path
                && validate_url_signature_request(req) == by
        }
    }

    fn ok_body(body: impl Into<String>) -> Response<String> {
        Response::builder()
            .status(StatusCode::OK)
            .body(body.into())
            .unwrap()
    }

    fn ok_typed(content_type: &str, body: impl Into<Vec<u8>>) -> Response<Vec<u8>> {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .body(body.into())
            .unwrap()
    }

    /// A sealed summary as indexd lists it with `includeslabs=false`, in the
    /// given response encoding.
    /// Built field by field from Go's JSON tags rather than from our own
    /// struct, so the test checks the wire format.
    fn summary_body(cbor: bool, sealed: &SealedObject, id: Hash256, size: u64) -> Vec<u8> {
        use ciborium::value::Value;

        let time = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        let bytes = |b: &[u8]| -> (Value, serde_json::Value) {
            (Value::Bytes(b.to_vec()), BASE64_STANDARD.encode(b).into())
        };
        let fields: Vec<(&str, Value, serde_json::Value)> = vec![
            (
                "objectID",
                Value::Bytes(AsRef::<[u8]>::as_ref(&id).to_vec()),
                serde_json::to_value(id).unwrap(),
            ),
            {
                let (c, j) = bytes(&sealed.encrypted_data_key);
                ("encryptedDataKey", c, j)
            },
            (
                "dataSignature",
                Value::Bytes(sealed.data_signature.as_ref().to_vec()),
                serde_json::to_value(&sealed.data_signature).unwrap(),
            ),
            {
                let (c, j) = bytes(&sealed.encrypted_metadata_key);
                ("encryptedMetadataKey", c, j)
            },
            {
                let (c, j) = bytes(&sealed.encrypted_metadata);
                ("encryptedMetadata", c, j)
            },
            (
                "metadataSignature",
                Value::Bytes(sealed.metadata_signature.as_ref().to_vec()),
                serde_json::to_value(&sealed.metadata_signature).unwrap(),
            ),
            (
                "createdAt",
                Value::Text(time(sealed.created_at)),
                time(sealed.created_at).into(),
            ),
            (
                "updatedAt",
                Value::Text(time(sealed.updated_at)),
                time(sealed.updated_at).into(),
            ),
            ("size", Value::Integer(size.into()), size.into()),
        ];
        if cbor {
            let map = fields
                .into_iter()
                .map(|(k, c, _)| (Value::Text(k.to_string()), c))
                .collect();
            let mut buf = Vec::new();
            ciborium::into_writer(&Value::Array(vec![Value::Map(map)]), &mut buf).unwrap();
            buf
        } else {
            let map: serde_json::Map<_, _> = fields
                .into_iter()
                .map(|(k, _, j)| (k.to_string(), j))
                .collect();
            serde_json::to_vec(&vec![map]).unwrap()
        }
    }

    /// Summaries decode from both response encodings and are requested with
    /// `includeslabs=false` so the indexer leaves the slabs out.
    #[tokio::test]
    async fn test_shared_object_summaries_wire_format() {
        let sharing_key = PrivateKey::from_seed(&rand::random());
        let object = Object {
            data_key: [9u8; 32].into(),
            slabs: vec![Slab {
                version: V0,
                encryption_key: [1u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([2u8; 32]),
                    host_key: PublicKey::new([3u8; 32]),
                }],
                offset: 0,
                length: 256,
            }],
            metadata: b"a movie".to_vec(),
            created_at: "2026-01-02T03:04:05.123456789Z".parse().unwrap(),
            updated_at: "2026-02-02T03:04:05Z".parse().unwrap(),
        };
        let sealed = object.seal_with(&sharing_key);
        let id = object.id();

        let size = 256;
        for cbor in [false, true] {
            let server = Server::run();
            let content_type = if cbor {
                "application/cbor"
            } else {
                "application/json"
            };
            server.expect(
                Expectation::matching(all_of![
                    signed_get("/shared/objects", sharing_key.public_key()),
                    request::query(url_decoded(contains(("includeslabs", "false")))),
                    request::query(url_decoded(contains(("limit", "10")))),
                ])
                .respond_with(ok_typed(
                    content_type,
                    summary_body(cbor, &sealed, id, size),
                )),
            );
            let client = Client::new(server.url("/").to_string()).unwrap();
            let summaries = client
                .shared_object_summaries(&sharing_key, Some(0), Some(10))
                .await
                .unwrap_or_else(|e| panic!("decode failed (cbor {cbor}): {e}"));
            assert_eq!(summaries.len(), 1);
            let summary = &summaries[0];
            assert_eq!(summary.object_id, id);
            assert_eq!(summary.size, size, "cbor {cbor}");
            assert_eq!(summary.encrypted_metadata, sealed.encrypted_metadata);
            assert_eq!(
                summary.encrypted_metadata_key,
                sealed.encrypted_metadata_key
            );
            assert_eq!(summary.metadata_signature, sealed.metadata_signature);
            assert_eq!(summary.created_at, object.created_at);
            assert_eq!(summary.updated_at, object.updated_at);
        }
    }

    #[tokio::test]
    async fn test_shared_endpoints_signed_with_sharing_key() {
        let sharing_key = PrivateKey::from_seed(&rand::random());
        let pk = sharing_key.public_key();
        let server = Server::run();

        let object = Object {
            data_key: [9u8; 32].into(),
            slabs: vec![Slab {
                version: V0,
                encryption_key: [1u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([2u8; 32]),
                    host_key: PublicKey::new([3u8; 32]),
                }],
                offset: 0,
                length: 256,
            }],
            ..Default::default()
        };
        let sealed = object.seal(&AppKey::import([7u8; 32]));
        let object_id = object.id();
        let shared_host = SharedHost {
            host: Host {
                public_key: PublicKey::new([4u8; 32]),
                addresses: vec![],
                country_code: "US".to_string(),
                latitude: 1.5,
                longitude: 2.5,
                good_for_upload: true,
            },
            token: AccountToken::new(
                &PrivateKey::from_seed(&[5u8; 32]),
                PublicKey::new([4u8; 32]),
            ),
        };

        let stats = KeyStats {
            object_count: 3,
            object_size: 1024,
            pinned_data: 2048,
            pinned_size: 6144,
            expires_at: None,
            created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
            updated_at: "2026-02-02T03:04:05Z".parse().unwrap(),
        };

        for (path, body) in [
            (
                "/shared".to_string(),
                serde_json::to_string(&stats).unwrap(),
            ),
            (
                "/shared/objects".to_string(),
                serde_json::to_string(&vec![sealed.clone()]).unwrap(),
            ),
            (
                format!("/shared/objects/{object_id}"),
                serde_json::to_string(&sealed).unwrap(),
            ),
            (
                "/shared/hosts".to_string(),
                serde_json::to_string(&vec![shared_host.clone()]).unwrap(),
            ),
        ] {
            server.expect(Expectation::matching(signed_get(path, pk)).respond_with(ok_body(body)));
        }

        let client = Client::new(server.url("/").to_string()).unwrap();

        assert_eq!(client.shared_stats(&sharing_key).await.unwrap(), stats);
        assert_eq!(
            client
                .shared_objects(&sharing_key, Some(0), Some(100))
                .await
                .unwrap(),
            vec![sealed.clone()]
        );
        assert_eq!(
            client
                .shared_object_by_id(&sharing_key, &object_id)
                .await
                .unwrap(),
            sealed
        );
        assert_eq!(
            client
                .shared_hosts(&sharing_key, HostQuery::default())
                .await
                .unwrap(),
            vec![shared_host]
        );
    }

    #[tokio::test]
    async fn test_owner_create_and_attach() {
        let app_key = PrivateKey::from_seed(&rand::random());
        let expected_pk = app_key.public_key();
        let sharing_key = PrivateKey::from_seed(&[6u8; 32]);
        let sharing_pub = sharing_key.public_key();
        let server = Server::run();

        let key = KeyResponse {
            public_key: sharing_pub,
            nonce: Nonce([7u8; 32]),
            account: expected_pk,
            description: "photos".to_string(),
            stats: KeyStats {
                object_count: 0,
                object_size: 0,
                pinned_data: 0,
                pinned_size: 0,
                expires_at: None,
                created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                updated_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
        };

        // POST /sharing -> the created key record, signed by the app key.
        let key_body = serde_json::to_string(&key).unwrap();
        server.expect(
            Expectation::matching(
                move |req: &httptest::http::Request<httptest::bytes::Bytes>| {
                    req.method() == "POST"
                        && req.uri().path() == "/sharing"
                        && validate_url_signature_request(req) == expected_pk
                },
            )
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(key_body)
                    .unwrap(),
            ),
        );

        // POST /sharing/<pub>/objects -> null (empty response).
        server.expect(
            Expectation::matching(request::method_path(
                "POST",
                format!("/sharing/{sharing_pub}/objects"),
            ))
            .respond_with(Response::builder().status(StatusCode::OK).body("").unwrap()),
        );

        let client = Client::new(server.url("/").to_string()).unwrap();

        let req = KeyRequest::new(&sharing_key, key.nonce, "photos".to_string(), None);
        let created = client.add_sharing_key(&app_key, &req).await.unwrap();
        assert_eq!(created, key);

        let object = Object {
            data_key: [9u8; 32].into(),
            slabs: vec![Slab {
                version: V0,
                encryption_key: [1u8; 32].into(),
                min_shards: 1,
                sectors: vec![Sector {
                    root: Hash256::new([2u8; 32]),
                    host_key: PublicKey::new([3u8; 32]),
                }],
                offset: 0,
                length: 256,
            }],
            ..Default::default()
        };
        let shared_req = SharedObjectRequest::new(&object, &sharing_key);
        client
            .add_shared_object(&app_key, &sharing_pub, &shared_req)
            .await
            .expect("attach object failed");
    }
}
