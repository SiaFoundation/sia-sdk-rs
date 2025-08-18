use sia::encoding_async::{AsyncDecoder, AsyncEncoder, EncodingError, Result as AsyncResult};
use sia::rhp::RPCSettings;
use url::Url;
use wasm_bindgen::prelude::*;
use web_sys::console;
use web_transport::ClientBuilder;

struct WebTransportStream {
    send: web_transport::SendStream,
    recv: web_transport::RecvStream,
}

impl AsyncEncoder for WebTransportStream {
    async fn write_all(&mut self, buf: &[u8]) -> AsyncResult<()> {
        self.send
            .write(buf)
            .await
            .map_err(|e| EncodingError::IOError(e.to_string()))
    }
}

impl AsyncDecoder for WebTransportStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> AsyncResult<()> {
        let mut n: usize = 0;
        while n < buf.len() {
            let res = self
                .recv
                .read(buf.len() - n)
                .await
                .map_err(|e| EncodingError::IOError(e.to_string()))?;
            match res {
                Some(bytes) => {
                    let end = n + bytes.len();
                    buf[n..end].copy_from_slice(&bytes);
                    n += bytes.len();
                    console::log_1(&JsValue::from_str(
                        format!("Read {} bytes ({}/{})", bytes.len(), n, buf.len()).as_str(),
                    ));
                }
                None => {
                    return Err(EncodingError::IOError(format!(
                        "failed to read bytes {}/{}",
                        n,
                        buf.len()
                    )));
                }
            };
        }
        Ok(())
    }
}

#[wasm_bindgen]
pub async fn get_host_settings(address: &str) -> Result<JsValue, JsError> {
    let client = ClientBuilder::new()
        .with_system_roots()
        .map_err(|e| JsError::new(&format!("Failed to create client: {}", e)))?;

    let mut session = client
        .connect(Url::parse(&format!("https://{}/sia/rhp/v4", address))?)
        .await
        .map_err(|e| JsError::new(&format!("Failed to connect: {}", e)))?;

    let (send, recv) = session
        .open_bi()
        .await
        .map_err(|e| JsError::new(&format!("Failed to open bi stream: {}", e)))?;
    let stream = WebTransportStream { send, recv };

    let result = RPCSettings::send_request(stream)
        .await
        .map_err(|e| JsError::new(&format!("Failed to send request: {}", e)))?
        .complete()
        .await
        .map_err(|e| JsError::new(&format!("Failed to complete request: {}", e)))?;

    console::log_1(&JsValue::from_str(
        format!("{:?}", result.settings).as_str(),
    ));
    serde_wasm_bindgen::to_value(&result.settings)
        .map_err(|e| JsError::new(&format!("Failed to serialize settings: {}", e)))
}
