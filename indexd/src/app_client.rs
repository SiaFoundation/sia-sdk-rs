use std::time::Duration;

use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use reqwest::{Method, StatusCode};
use serde_json::to_vec;
use sia::encryption::EncryptionKey;
use sia::rhp::Host;

use thiserror::Error;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::slabs::Sector;
use crate::{Object, PinnedSlab, SharedObject};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;

pub use reqwest::{IntoUrl, Url};

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

    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthConnectStatusResponse {
    approved: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAppRequest {
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
    pub expiration: DateTime<Utc>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SlabPinParams {
    pub encryption_key: EncryptionKey,
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

pub struct ObjectsCursor {
    pub after: DateTime<Utc>,
    pub key: Hash256,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account_key: PublicKey,
    pub service_account: bool,
    pub max_pinned_data: u64,
    pub pinned_data: u64,
    pub description: String,
    #[serde(rename = "logoURL")]
    pub logo_url: Option<String>,
    #[serde(rename = "serviceURL")]
    pub service_url: Option<String>,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Client {
    client: reqwest::Client,
    url: Url,
    app_key: PrivateKey,
}

/// A placeholder type that implements serde::Deserialize for endpoints that
/// return no content.
struct EmptyResponse;

impl<'de> serde::Deserialize<'de> for EmptyResponse {
    fn deserialize<D>(_: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(EmptyResponse)
    }
}

impl Client {
    pub fn new<U: IntoUrl>(url: U, app_key: PrivateKey) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            url: url.into_url()?,
            app_key,
        })
    }

    /// Checks if the application is authenticated with the indexer. It returns
    /// true if authenticated, false if not, and an error if the request fails.
    pub async fn check_app_authenticated(&self) -> Result<bool> {
        let url = self.url.join("auth/check")?;
        let query_params = self.sign(
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

    /// Checks if an auth request has been approved. If the auth request is
    /// still pending, it returns false.
    pub async fn check_request_status(&self, status_url: Url) -> Result<bool> {
        let query_params = self.sign(
            &status_url,
            Method::GET,
            None,
            Utc::now() + Duration::from_secs(60),
        );
        let resp = self
            .client
            .get(status_url)
            .timeout(Duration::from_secs(15))
            .query(&query_params)
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json::<AuthConnectStatusResponse>().await?.approved),
            StatusCode::NOT_FOUND => Err(Error::UserRejected),
            _ => Err(Error::Api(resp.text().await?)),
        }
    }

    /// Returns all usable hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>> {
        self.get_json::<_, ()>("hosts", None).await
    }

    /// Retrieves an object from the indexer by its key.
    pub async fn object(&self, key: &Hash256) -> Result<Object> {
        self.get_json::<_, ()>(&format!("objects/{key}"), None)
            .await
    }

    /// Fetches a list of objects from the indexer. Can be paginated using the
    /// cursor and limit arguments.
    pub async fn objects(
        &self,
        cursor: Option<ObjectsCursor>,
        limit: Option<usize>,
    ) -> Result<Vec<Object>> {
        let mut query_params = Vec::new();
        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(ObjectsCursor { after, key }) = cursor {
            query_params.push(("after", after.to_rfc3339())); // indexd expects RFC3339
            query_params.push(("key", key.to_string()));
        }
        self.get_json::<_, _>("objects", Some(&query_params)).await
    }

    /// Saves an object to the indexer.
    pub async fn save_object(&self, object: &Object) -> Result<()> {
        self.post_json::<_, EmptyResponse>("objects", object)
            .await
            .map(|_| ())
    }

    /// Deletes an object from the indexer by its key.
    pub async fn delete_object(&self, key: &Hash256) -> Result<()> {
        self.delete(&format!("objects/{key}")).await
    }

    /// Requests an application connection to the indexer.
    pub async fn request_app_connection(
        &self,
        opts: &RegisterAppRequest,
    ) -> Result<RegisterAppResponse> {
        self.post_json("auth/connect", opts).await
    }

    /// Retrieves a slab from the indexer by its ID.
    pub async fn slab(&self, slab_id: &Hash256) -> Result<PinnedSlab> {
        self.get_json::<_, ()>(&format!("slabs/{slab_id}"), None)
            .await
    }

    /// Fetches the digests of slabs associated with the account. It supports
    /// pagination through the provided options.
    pub async fn slab_ids(&self, offset: Option<u64>, limit: Option<u64>) -> Result<Vec<Hash256>> {
        #[derive(Serialize)]
        struct QueryParams {
            offset: Option<u64>,
            limit: Option<u64>,
        }
        let params = QueryParams { offset, limit };
        self.get_json("slabs", Some(&params)).await
    }

    /// Pins a slab to the indexer.
    pub async fn pin_slab(&self, slab: SlabPinParams) -> Result<Hash256> {
        self.post_json("slabs", &slab).await
    }

    /// Unpins a slab from the indexer.
    pub async fn unpin_slab(&self, slab_id: &Hash256) -> Result<()> {
        self.delete(&format!("slabs/{slab_id}")).await
    }

    /// Unpins slabs not used by any object on the account.
    pub async fn prune_slabs(&self) -> Result<()> {
        self.post_json::<_, EmptyResponse>("slabs/prune", &())
            .await
            .map(|_| ())
    }

    /// Account returns the current account.
    pub async fn account(&self) -> Result<Account> {
        self.get_json::<_, ()>("account", None).await
    }

    /// Helper to send a signed DELETE request.
    async fn delete(&self, path: &str) -> Result<()> {
        let url = self.url.join(path)?;
        let query_params = self.sign(
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
        query_params: Option<&Q>,
    ) -> Result<D> {
        let url = self.url.join(path)?;
        let params = self.sign(
            &url,
            Method::GET,
            None,
            Utc::now() + Duration::from_secs(60),
        );
        let mut builder = self.client.get(url).timeout(Duration::from_secs(15));
        if let Some(q) = query_params {
            builder = builder.query(q); // optional query params
        }
        Self::handle_response(builder.query(&params).send().await?).await
    }

    /// Helper to either parse a successfully JSON response or return the error
    /// message from the API.
    async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
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
        body: &S,
    ) -> Result<D> {
        let body = to_vec(body)?;
        let url = self.url.join(path)?;
        let query_params = self.sign(
            &url,
            Method::POST,
            Some(&body),
            Utc::now() + Duration::from_secs(60),
        );
        Self::handle_response(
            self.client
                .post(url)
                .query(&query_params)
                .timeout(Duration::from_secs(15))
                .body(body)
                .send()
                .await?,
        )
        .await
    }

    fn request_hash(
        url: &Url,
        method: Method,
        body: Option<&[u8]>,
        valid_until: DateTime<Utc>,
    ) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state
            .update(method.as_str().as_bytes())
            .update(url.host_str().unwrap_or("").as_bytes())
            .update(url.path().as_bytes())
            .update(&valid_until.timestamp().to_le_bytes());
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
    /// - `object_key` the key of the object
    /// - `encryption_key` the key used to encrypt the metadata
    /// - `valid_until` the time the link expires
    pub fn object_share_url(
        &self,
        object_key: &Hash256,
        encryption_key: [u8; 32],
        valid_until: DateTime<Utc>,
    ) -> Result<Url> {
        let mut url = self
            .url
            .join(format!("objects/{}/shared", object_key).as_str())?;

        let params = self.sign(&url, Method::GET, None, valid_until);

        url.set_fragment(Some(
            format!("encryption_key={}", hex::encode(encryption_key)).as_str(),
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
    pub async fn shared_object(&self, mut share_url: Url) -> Result<(SharedObject, [u8; 32])> {
        let encryption_key = match share_url.fragment() {
            Some(fragment) => {
                let fragment = match fragment.strip_prefix("encryption_key=") {
                    Some(fragment) => Ok(fragment),
                    None => Err(Error::Format("missing encryption_key".into())),
                }?;
                let mut out = [0u8; 32];
                hex::decode_to_slice(fragment, &mut out).map_err(|_| {
                    Error::Format("encryption key must be 32 hex-encoded bytes".into())
                })?;
                Ok(out)
            }
            None => Err(Error::Format("missing encryption_key".into())),
        }?;
        share_url.set_fragment(None);
        let obj = Self::handle_response(
            self.client
                .get(share_url)
                .timeout(Duration::from_secs(15))
                .send()
                .await?,
        )
        .await?;

        Ok((obj, encryption_key))
    }

    fn sign(
        &self,
        url: &Url,
        method: Method,
        body: Option<&[u8]>,
        valid_until: DateTime<Utc>,
    ) -> [(&'static str, String); 3] {
        let hash = Self::request_hash(url, method, body, valid_until);
        [
            ("SiaIdx-ValidUntil", valid_until.timestamp().to_string()),
            ("SiaIdx-Credential", self.app_key.public_key().to_string()),
            (
                "SiaIdx-Signature",
                self.app_key.sign(hash.as_ref()).to_string(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::{Object, SlabSlice};
    use chrono::FixedOffset;
    use sia::{hash_256, public_key};

    use super::*;
    use httptest::http::Response;
    use httptest::matchers::*;
    use httptest::{Expectation, Server};

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
        let client = Client::new("https://foo.bar", app_key).unwrap();

        // with body
        let params = client.sign(
            &"https://foo.bar/baz.jpg".parse().unwrap(),
            Method::POST,
            Some("{}".as_bytes()),
            DateTime::from_timestamp_secs(123).unwrap() + Duration::from_secs(60),
        );
        assert_eq!(params[0], ("SiaIdx-ValidUntil", "183".to_string()));
        assert_eq!(
            params[1],
            (
                "SiaIdx-Credential",
                "ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
                    .to_string()
            )
        );
        assert_eq!(
            params[2],
            (
                "SiaIdx-Signature",
                "458283fd707c9d170d5e1814944f35893c53c9445fd46c74a6b285bf3029bf404c9af509ea271d811726bd20d8c7d8fe4b9efdc4bebb445f18059eca886ece03"
                    .to_string()
            )
        );

        // without body
        let params = client.sign(
            &"https://foo.bar/baz.jpg".parse().unwrap(),
            Method::GET,
            None,
            DateTime::from_timestamp_secs(123).unwrap() + Duration::from_secs(60),
        );
        assert_eq!(params[0], ("SiaIdx-ValidUntil", "183".to_string()));
        assert_eq!(
            params[1],
            (
                "SiaIdx-Credential",
                "ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
                    .to_string()
            )
        );
        assert_eq!(
            params[2],
            (
                "SiaIdx-Signature",
                "7411fc80f920cb098690498133be075cd43bf6385fc8348fe1946e29d909891680d45651dfb0a6fd9f7196a971816c21441852362680f2fe4cb935de8f90380b"
                    .to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_signed_auth() {
        let server = Server::run();

        // expect 1 authenticated get and 1 authenticated post request
        server.expect(
            Expectation::matching(request::query(url_decoded(all_of![
                contains(("SiaIdx-ValidUntil", any())),
                contains(("SiaIdx-Credential", any())),
                contains(("SiaIdx-Signature", any()))
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        let _: Result<()> = client.get_json::<_, ()>("", None).await;
        let _: Result<()> = client.post_json("", &"").await;
        let _: Result<()> = client.delete("").await;
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
          "encryptionKey": [186,153,179,170,159,95,101,177,15,130,58,19,138,144,9,91,181,119,38,225,209,47,149,22,157,210,16,232,10,151,186,160],
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(client.slab(&slab.id).await.unwrap(), slab);
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(
            client.slab_ids(Some(1), Some(2)).await.unwrap(),
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
                request::body(serde_json::to_string(&slab).unwrap())
            ])
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("\"43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28\"")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(client.pin_slab(slab).await.unwrap(), slab_id);
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        client.unpin_slab(&slab_id).await.unwrap();
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();

        let expected_error = Error::Api("something went wrong".to_string());
        let get_error = client.get_json::<(), ()>("", None).await.unwrap_err();
        assert_eq!(get_error.to_string(), expected_error.to_string());
        let post_error = client.post_json::<(), ()>("", &()).await.unwrap_err();
        assert_eq!(post_error.to_string(), expected_error.to_string());
        let delete_error = client.delete("").await.unwrap_err();
        assert_eq!(delete_error.to_string(), expected_error.to_string());
    }

    #[tokio::test]
    async fn test_check_request_status() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/approved")).respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body("{\"approved\": true}")
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

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new("https://foo.com", app_key).unwrap();

        // approved request
        let status_url: Url = server.url("/approved").to_string().parse().unwrap();
        assert!(client.check_request_status(status_url).await.unwrap());

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
        let client = Client::new(server.url("").to_string(), app_key).unwrap();

        // approved request
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check")).respond_with(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body("")
                    .unwrap(),
            ),
        );
        assert!(client.check_app_authenticated().await.unwrap());

        // rejected request
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check")).respond_with(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("")
                    .unwrap(),
            ),
        );
        assert!(!client.check_app_authenticated().await.unwrap());

        // other error
        server.expect(
            Expectation::matching(request::method_path("GET", "/auth/check")).respond_with(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("something went wrong")
                    .unwrap(),
            ),
        );
        let err = client.check_app_authenticated().await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "indexd responded with an error: something went wrong"
        );
    }

    #[tokio::test]
    async fn test_request_app_connection() {
        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/auth/connect"),
                request::body(r#"{"name":"name","description":"description","serviceURL":"https://service.com/","logoURL":"https://logo.com/","callbackURL":"https://callback.com/"}"#),
            ])
                .respond_with(Response::builder().status(StatusCode::OK).body(r#"{"responseURL":"https://response.com","statusURL":"https://status.com","expiration":"1970-01-01T01:01:40+01:00"}"#).unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();

        let resp = client
            .request_app_connection(&RegisterAppRequest {
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
                response_url: "https://response.com".to_string(),
                status_url: "https://status.com".to_string(),
                expiration: DateTime::from_timestamp_secs(100).unwrap(),
            }
        )
    }

    #[tokio::test]
    async fn test_object() {
        let object = Object {
            key: hash_256!("1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef"),
            slabs: vec![
                SlabSlice {
                    slab_id: hash_256!(
                        "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2"
                    ),
                    offset: 0,
                    length: 256,
                },
                SlabSlice {
                    slab_id: hash_256!(
                        "281a9c3fc1d74012ed4659a7fbd271237322e757e6427b561b73dbd9b3e09405"
                    ),
                    offset: 256,
                    length: 512,
                },
            ],
            meta: b"hello world!".to_vec().into(),
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
          "key": "1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef",
          "slabs": [
           {
            "slabID": "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2",
            "offset": 0,
            "length": 256
           },
           {
            "slabID": "281a9c3fc1d74012ed4659a7fbd271237322e757e6427b561b73dbd9b3e09405",
            "offset": 256,
            "length": 512
           }
          ],
          "meta": "aGVsbG8gd29ybGQh",
          "createdAt": "2025-09-09T16:10:46.898399-07:00",
          "updatedAt": "2025-09-09T16:10:46.898399-07:00"
         }
        "#;

        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/objects/1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef",
            ))
            .respond_with(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(TEST_OBJECT_JSON)
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(client.object(&object.key).await.unwrap(), object);
    }

    #[tokio::test]
    async fn test_objects() {
        let object = Object {
            key: hash_256!("1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef"),
            slabs: vec![
                SlabSlice {
                    slab_id: hash_256!(
                        "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2"
                    ),
                    offset: 0,
                    length: 256,
                },
                SlabSlice {
                    slab_id: hash_256!(
                        "281a9c3fc1d74012ed4659a7fbd271237322e757e6427b561b73dbd9b3e09405"
                    ),
                    offset: 256,
                    length: 512,
                },
            ],
            meta: b"hello world!".to_vec().into(),
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

        const TEST_OBJECTS_JSON: &str = r#"
        [{
          "key": "1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef",
          "slabs": [
           {
            "slabID": "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2",
            "offset": 0,
            "length": 256
           },
           {
            "slabID": "281a9c3fc1d74012ed4659a7fbd271237322e757e6427b561b73dbd9b3e09405",
            "offset": 256,
            "length": 512
           }
          ],
          "meta": "aGVsbG8gd29ybGQh",
          "createdAt": "2025-09-09T16:10:46.898399-07:00",
          "updatedAt": "2025-09-09T16:10:46.898399-07:00"
         }]
        "#;

        let server = Server::run();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/objects"),
                request::query(url_decoded(all_of![
                    contains(("after", "2025-09-09T23:10:46.898399+00:00")),
                    contains((
                        "key",
                        "1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef"
                    )),
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(
            client
                .objects(
                    Some(ObjectsCursor {
                        after: object.updated_at.into(),
                        key: object.key,
                    }),
                    Some(1)
                )
                .await
                .unwrap(),
            vec![object]
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        client.delete_object(&object_key).await.unwrap();
    }

    #[tokio::test]
    async fn save_object() {
        let object = Object {
            key: hash_256!("1a1fcd352cdf56f5da73a566b58d764afc8cd8bfb30ef4e786b031227356d2ef"),
            slabs: vec![
                SlabSlice {
                    slab_id: hash_256!(
                        "3ceeb79f58b0c4f67775e0a06aa7241c461e6844b4700a94e0a31e4d22dd02c2"
                    ),
                    offset: 0,
                    length: 256,
                },
                SlabSlice {
                    slab_id: hash_256!(
                        "281a9c3fc1d74012ed4659a7fbd271237322e757e6427b561b73dbd9b3e09405"
                    ),
                    offset: 256,
                    length: 512,
                },
            ],
            meta: b"hello world!".to_vec().into(),
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
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        client.save_object(&object).await.unwrap();
    }
}
