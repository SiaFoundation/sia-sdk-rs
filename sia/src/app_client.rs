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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sector {
    pub root: SlabID,
    pub host_key: PublicKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Slab {
    pub id: SlabID,
    pub encryption_key: [u8; 32],
    pub min_shards: u8,
    pub sectors: Vec<Sector>,
}

#[derive(Debug, Serialize)]
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
    use httptest::{Expectation, Server, matchers::*, responders::*};

    #[tokio::test]
    async fn test_slab() {
        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path("GET", "/slab"))
                .respond_with(Response::builder().status(200).body("{}").unwrap()),
        );

        let client = Client::new(server.url("/").to_string(), Some("password".to_string()));

        // TODO: set body
        match client.slab().await {
            Ok(slab) => println!("Retrieved slab: {:?}", slab),
            Err(e) => eprintln!("Error retrieving slab: {}", e),
        }
    }
}
