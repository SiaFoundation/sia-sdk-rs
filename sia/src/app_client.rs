use crate::signing::PrivateKey;

trait AppClient {}

struct Client {
    client: reqwest::Client,
    url: String,
    password: Option<String>,
}

impl Client {
    fn new(url: String, password: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            password,
        }
    }

    fn get(&self) -> reqwest::RequestBuilder {
        self.client
            .get(&self.url)
            .basic_auth("user", self.password.clone())
    }

    fn post(&self) -> reqwest::RequestBuilder {
        self.client
            .post(&self.url)
            .basic_auth("user", self.password.clone())
    }

    async fn slab(&self) {
        unimplemented!()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.clear();
        }
    }
}
