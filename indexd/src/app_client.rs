use blake2b_simd::Params;
use reqwest::{IntoUrl, Method, StatusCode, Url};
use serde_json::to_vec;
use sia::types::v2::NetAddress;
use thiserror::Error;
use time::OffsetDateTime;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sia::objects::slabs::Sector;
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;

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
pub struct Host {
    pub public_key: PublicKey,
    pub addresses: Vec<NetAddress>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAppRequest {
    pub name: String,
    pub description: Option<String>,
    pub logo_url: Option<Url>,
    pub service_url: Option<Url>,
    pub callback_url: Option<Url>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAppResponse {
    pub response_url: String,
    pub status_url: String,
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
    #[allow(dead_code)]
    pub fn new<U: IntoUrl>(url: U, app_key: PrivateKey) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            url: url.into_url()?,
            app_key,
        })
    }

    pub async fn check_app_authenticated(&self, status_url: &Url) -> Result<bool> {
        let resp = self
            .client
            .get(status_url.clone())
            .query(&self.sign(
                status_url.clone(),
                Method::POST,
                None,
                OffsetDateTime::now_utc(),
            ))
            .send()
            .await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::NO_CONTENT => Ok(true),
            _ => Err(Error::ApiError(resp.text().await?)),
        }
    }

    pub async fn check_request_status(
        &self,
        status_url: &Url,
    ) -> Result<AuthConnectStatusResponse> {
        let resp = self
            .client
            .get(status_url.clone())
            .query(&self.sign(
                status_url.clone(),
                Method::POST,
                None,
                OffsetDateTime::now_utc(),
            ))
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(resp.json().await?),
            StatusCode::NOT_FOUND => Err(Error::UserRejected),
            _ => Err(Error::ApiError(resp.text().await?)),
        }
    }

    async fn handle_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        if resp.status().is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            Err(Error::ApiError(resp.text().await?))
        }
    }

    #[allow(dead_code)]
    pub async fn hosts(&self) -> Result<Vec<Host>> {
        self.get_json::<_, ()>("hosts", None).await
    }

    #[allow(dead_code)]
    pub async fn request_app_connection(
        &self,
        opts: &RegisterAppRequest,
    ) -> Result<RegisterAppResponse> {
        self.post_json("auth/connect", opts).await
    }

    #[allow(dead_code)]
    pub async fn slab(&self, slab_id: &Hash256) -> Result<Slab> {
        self.get_json::<_, ()>(&format!("slab/{slab_id}"), None)
            .await
    }

    #[allow(dead_code)]
    pub async fn slab_ids(&self, offset: Option<u64>, limit: Option<u64>) -> Result<Vec<Hash256>> {
        #[derive(Serialize)]
        struct QueryParams {
            offset: Option<u64>,
            limit: Option<u64>,
        }
        let params = QueryParams { offset, limit };
        self.get_json("slabs", Some(&params)).await
    }

    #[allow(dead_code)]
    pub async fn pin_slab(&self, slab: &SlabPinParams) -> Result<Hash256> {
        self.post_json("slabs", &slab).await
    }

    #[allow(dead_code)]
    pub async fn unpin_slab(&self, slab_id: &Hash256) -> Result<()> {
        self.delete(&format!("slabs/{slab_id}")).await
    }

    /// Helper to send a signed DELETE request.
    async fn delete(&self, path: &str) -> Result<()> {
        let url = self.url.join(path)?;
        Self::handle_response(
            self.client
                .delete(url.clone())
                .query(&self.sign(url, Method::DELETE, None, OffsetDateTime::now_utc()))
                .send()
                .await?,
        )
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
        let mut builder = self.client.get(url.clone());
        if let Some(q) = query_params {
            builder = builder.query(q); // optional query params
        }
        Self::handle_response(
            builder
                .query(&self.sign(url, Method::GET, None, OffsetDateTime::now_utc()))
                .send()
                .await?,
        )
        .await
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
        Self::handle_response(
            self.client
                .post(url.clone())
                .query(&self.sign(url, Method::POST, Some(&body), OffsetDateTime::now_utc()))
                .body(body)
                .send()
                .await?,
        )
        .await
    }

    fn request_hash(
        url: Url,
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
        url: Url,
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
        let hash = Client::request_hash(url, method, Some(body), valid_until);
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
            "https://foo.bar/baz.jpg".parse().unwrap(),
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
            "https://foo.bar/baz.jpg".parse().unwrap(),
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
            .respond_with(Response::builder().status(200).body("{}").unwrap()),
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
                    .status(200)
                    .body(TEST_SLAB_JSON)
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(client.slab(&slab.id).await.unwrap(), slab);
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
                    .status(200)
                    .body("\"43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28\"")
                    .unwrap(),
            ),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        assert_eq!(client.pin_slab(&slab).await.unwrap(), slab_id);
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
        let status = client.check_request_status(&status_url).await.unwrap();
        assert!(status.approved);

        // rejected request
        let status_url: Url = server.url("/rejected").to_string().parse().unwrap();
        assert!(matches!(
            client.check_request_status(&status_url).await.unwrap_err(),
            Error::UserRejected,
        ));

        // other error
        let status_url: Url = server.url("/error").to_string().parse().unwrap();
        let err = client.check_request_status(&status_url).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "indexd responded with an error: something went wrong"
        );
    }

    #[tokio::test]
    async fn test_check_app_auth() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/approved")).respond_with(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body("")
                    .unwrap(),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/rejected")).respond_with(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
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
        assert!(client.check_app_authenticated(&status_url).await.unwrap());

        // rejected request
        let status_url: Url = server.url("/rejected").to_string().parse().unwrap();
        assert!(!client.check_app_authenticated(&status_url).await.unwrap());

        // other error
        let status_url: Url = server.url("/error").to_string().parse().unwrap();
        let err = client
            .check_app_authenticated(&status_url)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "indexd responded with an error: something went wrong"
        );
    }
}
