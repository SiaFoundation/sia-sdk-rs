use std::fmt;
use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::{
    signing::{PrivateKey, PublicKey},
    types::Hash256,
};

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
    fn new(url: String, password: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_string(),
            password,
        }
    }

    async fn slab(&self) -> Result<Slab> {
        let slab: Slab = self
            .client
            .get(format!("{}/slab", self.url))
            .basic_auth("", self.password.clone())
            .send()
            .await
            .unwrap()
            .json()
            .await?;
        Ok(slab)
    }

    async fn pin_slab(&self, params: SlabPinParams) -> Result<Hash256> {
        let slab_id: Hash256 = self
            .client
            .post(format!("{}/slabs", self.url))
            .basic_auth("", self.password.clone())
            .json(&params)
            .send()
            .await?
            .json()
            .await?;
        Ok(slab_id)
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

        const TEST_SLAB_JSON: &str = "\"{\"id\":\"43e424e1fc0e8b4fab0b49721d3ccb73fe1d09eef38227d9915beee623785f28\",\"encryptionKey\":[186,153,179,170,159,95,101,177,15,130,58,19,138,144,9,91,181,119,38,225,209,47,149,22,157,210,16,232,10,151,186,160],\"minShards\":1,\"sectors\":[{\"root\":\"826af7ab6471d01f4a912903a9dc23d59cff3b151059fa25615322bbf41634d6\",\"hostKey\":\"ed25519:470c3cbd5498ba161379823c0c9d24c6e6b325d1a9fe1f215689f3ef297bf530\"},{\"root\":\"623e6c88c40b9d2c7e9654c399161ea072b34db81db7e7e81df0093cbe7edd73\",\"hostKey\":\"ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe\"},{\"root\":\"c92d003c2c3fc38bc6f48e3f50d8dbc5e04ed2da33b22df64b366ff48b1d35b9\",\"hostKey\":\"ed25519:273d9e37288d7a24cc3b5ef167b918a9d3ebf2274f90d26a7c249ab609086e93\"}]}\r\n        slab {\"id\":\"329032cd99e5f22a84b8667d9b846f86b8b0f44dae453a56328fd7485f5b77e1\",\"encryptionKey\":[8,59,228,167,205,24,51,197,204,203,42,51,119,190,199,244,122,116,139,173,248,254,200,80,241,214,24,64,1,35,21,245],\"minShards\":1,\"sectors\":[{\"root\":\"d421bedac94a7ddd9f61c8847dd7be52617d6d023f6d2c07d2665cf0ccc4a851\",\"hostKey\":\"ed25519:470c3cbd5498ba161379823c0c9d24c6e6b325d1a9fe1f215689f3ef297bf530\"},{\"root\":\"d11b3bdc87fb34de413edb9253ad96b141115b7396b74b1b9ef5f6d70a140edb\",\"hostKey\":\"ed25519:910b22c360a1c67cb6a9a7371fa600c48e87d626b328669d01f34048ac3132fe\"},{\"root\":\"a077d0da3ea2fda0b18b28825b8f0e43c74bcec32fe1607940cf24e919c54960\",\"hostKey\":\"ed25519:273d9e37288d7a24cc3b5ef167b918a9d3ebf2274f90d26a7c249ab609086e93\"}]}\'\r\n";

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
