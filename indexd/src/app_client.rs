use reqwest::Body;
use thiserror::Error;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use sia::objects::slabs::Sector;
use sia::types::Hash256;

#[derive(Debug, Error)]
pub enum Error {
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    client: reqwest::Client,
    url: String,
    password: Option<String>,
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
    pub fn new(url: String, password: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_string(),
            password,
        }
    }

    #[allow(dead_code)]
    pub async fn slab(&self, slab_id: &Hash256) -> Result<Slab> {
        self.get_json(&format!("/slab/{slab_id}")).await
    }

    #[allow(dead_code)]
    pub async fn pin_slab(&self, slab: &SlabPinParams) -> Result<Hash256> {
        self.post_json("/slabs", serde_json::to_string(&slab)?)
            .await
    }

    /// Helper to send a GET request with basic auth and parse the JSON
    /// response.
    async fn get_json<D: DeserializeOwned>(&self, path: &str) -> Result<D> {
        Ok(self
            .client
            .get(format!("{}{}", self.url, path))
            .basic_auth("", self.password.clone())
            .send()
            .await?
            .json::<D>()
            .await?)
    }

    // Helper to send a POST request with basic auth and parse the JSON
    // response.
    async fn post_json<B: Into<Body>, D: DeserializeOwned>(
        &self,
        path: &str,
        body: B,
    ) -> Result<D> {
        Ok(self
            .client
            .post(format!("{}{}", self.url, path))
            .basic_auth("", self.password.clone())
            .body(body)
            .send()
            .await?
            .json::<D>()
            .await?)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
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

        let client = Client::new(server.url("/").to_string(), Some("password".to_string()));
        let _: Result<()> = client.get_json("/").await;
        let _: Result<()> = client.post_json("/", "").await;
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

        let client = Client::new(server.url("/").to_string(), Some("password".to_string()));
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

        let client = Client::new(server.url("/").to_string(), Some("password".to_string()));
        assert_eq!(client.pin_slab(&slab).await.unwrap(), slab_id);
    }
}
