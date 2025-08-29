use blake2b_simd::Params;
use reqwest::header::HeaderMap;
use reqwest::{Body, IntoUrl, Method, Request, Url};
use serde_json::{to_string, to_vec};
use thiserror::Error;
use time::OffsetDateTime;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sia::objects::slabs::Sector;
use sia::signing::PrivateKey;
use sia::types::Hash256;

#[derive(Debug, Error)]
pub enum Error {
    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    client: reqwest::Client,
    url: Url,
    app_key: PrivateKey,
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

    #[allow(dead_code)]
    pub async fn slab(&self, slab_id: &Hash256) -> Result<Slab> {
        self.get_json(&format!("/slab/{slab_id}")).await
    }

    #[allow(dead_code)]
    pub async fn pin_slab(&self, slab: &SlabPinParams) -> Result<Hash256> {
        self.post_json("/slabs", &slab).await
    }

    /// Helper to send a GET request with basic auth and parse the JSON
    /// response.
    async fn get_json<D: DeserializeOwned>(&self, path: &str) -> Result<D> {
        let url = format!("{}{}", self.url, path);
        Ok(self
            .client
            .get(&url)
            .headers(self.sign(&url, Method::GET, None))
            .send()
            .await?
            .json::<D>()
            .await?)
    }

    // Helper to send a POST request with basic auth and parse the JSON
    // response.
    async fn post_json<S: Serialize, D: DeserializeOwned>(
        &self,
        path: &str,
        body: &S,
    ) -> Result<D> {
        let body = to_vec(body)?;
        let url = format!("{}{}", self.url, path);
        Ok(self
            .client
            .post(&url)
            .headers(self.sign(&url, Method::POST, Some(&body)))
            .body(body)
            .send()
            .await?
            .json::<D>()
            .await?)
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

    fn sign<U: IntoUrl>(&self, url: U, method: Method, body: Option<&[u8]>) -> HeaderMap {
        let valid_until = OffsetDateTime::now_utc() + time::Duration::hours(1);
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use sia::{hash_256, public_key};

    use super::*;
    use httptest::http::Response;
    use httptest::matchers::*;
    use httptest::{Expectation, Server};

    #[tokio::test]
    async fn test_basic_auth() {
        let server = Server::run();

        // expect 1 authenticated get and 1 authenticated post request
        server.expect(
            Expectation::matching(request::headers(contains((
                "authorization",
                "Basic OnBhc3N3b3Jk",
            ))))
            .times(2)
            .respond_with(Response::builder().status(200).body("{}").unwrap()),
        );

        let app_key = PrivateKey::from_seed(&rand::random());
        let client = Client::new(server.url("/").to_string(), app_key).unwrap();
        let _: Result<()> = client.get_json("/").await;
        let _: Result<()> = client.post_json("/", &"").await;
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
}
