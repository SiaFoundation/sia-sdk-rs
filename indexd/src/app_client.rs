use blake2b_simd::Params;
use reqwest::{Method, StatusCode};
use serde_json::to_vec;
use sia::rhp::Host;
use thiserror::Error;
use time::OffsetDateTime;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sia::objects::slabs::Sector;
use sia::signing::PrivateKey;
use sia::types::Hash256;

pub use reqwest::{IntoUrl, Url};

#[derive(Debug, Error)]
pub enum Error {
    #[error("indexd responded with an error: {0}")]
    ApiError(String),

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
}

type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    client: reqwest::Client,
    url: Url,
    app_key: PrivateKey,
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
    pub description: Option<String>,
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
    #[serde(with = "time::serde::rfc3339")]
    pub expiration: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Slab {
    pub id: Hash256,
    pub encryption_key: [u8; 32],
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SlabPinParams {
    pub encryption_key: [u8; 32],
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
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
        let query_params = self.sign(&url, Method::GET, None, OffsetDateTime::now_utc());
        let resp = self.client.get(url).query(&query_params).send().await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::NO_CONTENT => Ok(true),
            _ => Err(Error::ApiError(resp.text().await?)),
        }
    }

    /// Checks if an auth request has been approved. If the auth request is
    /// still pending, it returns false.
    pub async fn check_request_status(&self, status_url: Url) -> Result<bool> {
        let query_params = self.sign(&status_url, Method::GET, None, OffsetDateTime::now_utc());
        let resp = self
            .client
            .get(status_url)
            .query(&query_params)
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json::<AuthConnectStatusResponse>().await?.approved),
            StatusCode::NOT_FOUND => Err(Error::UserRejected),
            _ => Err(Error::ApiError(resp.text().await?)),
        }
    }

    /// Returns all usable hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>> {
        self.get_json::<_, ()>("hosts", None).await
    }

    /// Requests an application connection to the indexer.
    pub async fn request_app_connection(
        &self,
        opts: &RegisterAppRequest,
    ) -> Result<RegisterAppResponse> {
        self.post_json("auth/connect", opts).await
    }

    /// Retrieves a slab from the indexer by its ID.
    pub async fn slab(&self, slab_id: &Hash256) -> Result<Slab> {
        self.get_json::<_, ()>(&format!("slab/{slab_id}"), None)
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
    pub async fn pin_slab(&self, slab: &SlabPinParams) -> Result<Hash256> {
        self.post_json("slabs", &slab).await
    }

    /// Unpins a slab from the indexer.
    pub async fn unpin_slab(&self, slab_id: &Hash256) -> Result<()> {
        self.delete(&format!("slabs/{slab_id}")).await
    }

    /// Helper to send a signed DELETE request.
    async fn delete(&self, path: &str) -> Result<()> {
        let url = self.url.join(path)?;
        let query_params = self.sign(&url, Method::DELETE, None, OffsetDateTime::now_utc());
        Self::handle_empty_response(self.client.delete(url).query(&query_params).send().await?)
            .await
    }

    /// Helper to send a signed GET request and parse the JSON
    /// response.
    async fn get_json<D: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        path: &str,
        query_params: Option<&Q>,
    ) -> Result<D> {
        let url = self.url.join(path)?;
        let params = self.sign(&url, Method::GET, None, OffsetDateTime::now_utc());
        let mut builder = self.client.get(url);
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
            Err(Error::ApiError(resp.text().await?))
        }
    }

    /// Same as handle_response but for empty responses.
    async fn handle_empty_response(resp: reqwest::Response) -> Result<()> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::ApiError(resp.text().await?))
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
        let query_params = self.sign(&url, Method::POST, Some(&body), OffsetDateTime::now_utc());
        Self::handle_response(
            self.client
                .post(url)
                .query(&query_params)
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
        valid_until: time::OffsetDateTime,
    ) -> Hash256 {
        let mut state = Params::new().hash_length(32).to_state();
        state
            .update(method.as_str().as_bytes())
            .update(url.host_str().unwrap_or("").as_bytes())
            .update(&valid_until.unix_timestamp().to_le_bytes());
        if let Some(body) = body {
            state.update(body);
        }
        state.finalize().into()
    }

    fn sign(
        &self,
        url: &Url,
        method: Method,
        body: Option<&[u8]>,
        current_time: OffsetDateTime,
    ) -> [(&'static str, String); 3] {
        let valid_until = current_time + time::Duration::hours(1);
        let hash = Self::request_hash(url, method, body, valid_until);
        [
            (
                "SiaIdx-ValidUntil",
                valid_until.unix_timestamp().to_string(),
            ),
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
    use sia::{hash_256, public_key};

    use super::*;
    use httptest::http::Response;
    use httptest::matchers::*;
    use httptest::{Expectation, Server};

    #[test]
    fn test_request_hash() {
        let method = Method::POST;
        let url = Url::parse("https://foo.bar").unwrap();
        let valid_until = OffsetDateTime::from_unix_timestamp(123).unwrap();
        let body = b"hello world!";
        let hash = Client::request_hash(&url, method, Some(body), valid_until);
        assert_eq!(
            hash,
            hash_256!("b94c04c0a6ffbac6bfa9ce847d2a5de34db3bc33ac4824412acf2597ba043bce")
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
            OffsetDateTime::from_unix_timestamp(123).unwrap(),
        );
        assert_eq!(params[0], ("SiaIdx-ValidUntil", "3723".to_string()));
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
                "8046d35eb80ea9cf8a4b1f3478bb1508bfc6aa1c4617e2841f32684c3f39b59fff02f9283e37976da2f5e5b4e2f3c9f1640228a451c29be3024a9a3271af4e0a"
                    .to_string()
            )
        );

        // without body
        let params = client.sign(
            &"https://foo.bar/baz.jpg".parse().unwrap(),
            Method::GET,
            None,
            OffsetDateTime::from_unix_timestamp(123).unwrap(),
        );
        assert_eq!(params[0], ("SiaIdx-ValidUntil", "3723".to_string()));
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
                "40b37ae7db469c351797bc69e01277a8818d75b6cbcef922f0cffedd4229bcecdbdcf038010badda0eb35c38171bcc41aca5e4fab2f639bcd93e54aec3ef8005"
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
        let slab = Slab {
            id: "43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28"
                .parse()
                .unwrap(),
            encryption_key: [
                186, 153, 179, 170, 159, 95, 101, 177, 15, 130, 58, 19, 138, 144, 9, 91, 181, 119,
                38, 225, 209, 47, 149, 22, 157, 210, 16, 232, 10, 151, 186, 160,
            ],
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
                "/slab/43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28",
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
            ],
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
        assert_eq!(client.pin_slab(&slab).await.unwrap(), slab_id);
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

        let expected_error = Error::ApiError("something went wrong".to_string());
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
                description: Some("description".to_string()),
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
                expiration: OffsetDateTime::from_unix_timestamp(100).unwrap(),
            }
        )
    }
}
