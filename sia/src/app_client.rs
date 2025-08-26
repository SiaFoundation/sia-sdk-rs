use thiserror::Error;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{signing::PublicKey, types::Hash256};

#[derive(Debug, Error)]
enum Error {
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

struct Client {
    client: reqwest::Client,
    url: String,
    password: Option<String>,
}

type SlabID = Hash256;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sector {
    pub root: SlabID,
    pub host_key: PublicKey,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Slab {
    pub id: SlabID,
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
    pub async fn slab(&self) -> Result<Slab> {
        self.get_json("/slab").await
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
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::http::Response;
    use httptest::{Expectation, Server, matchers::*};

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
                root: "826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6"
                    .parse()
                    .unwrap(),
                host_key:
                    "ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe"
                        .parse()
                        .unwrap(),
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
            Expectation::matching(request::method_path("GET", "/slab")).respond_with(
                Response::builder()
                    .status(200)
                    .body(TEST_SLAB_JSON)
                    .unwrap(),
            ),
        );

        let client = Client::new(server.url("/").to_string(), Some("password".to_string()));
        assert_eq!(client.slab().await.unwrap(), slab);
    }
}
