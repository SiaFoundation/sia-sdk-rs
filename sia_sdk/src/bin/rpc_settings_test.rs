use sia_sdk::rpc::{self, AsyncRead, AsyncWrite};
use std::io;
use web_transport;

#[tokio::main]
async fn main() {
    let client = unsafe {
        web_transport::quinn::ClientBuilder::default().with_no_certificate_verification()
    }
    .unwrap();

    let session = client
        .connect(
            "https://127.0.0.1:49829/sia/rhp/v4"
                //"https://2l8dvkho84abi14l313c4r48267fhffujsbk9hkvproe1rmkhme0.sia.host:9984/sia/rhp/v4"
                .parse()
                .unwrap(),
        )
        .await
        .expect("failed to establish connection");

    let mut session = web_transport::Session::from(session);
    let (sender, receiver) = session.open_bi().await.unwrap();

    let stream = WebtransportStream::new(sender, receiver);

    let res = rpc::rpc_settings(stream).await.unwrap();
    println!("result {:?}", res.settings)
}

pub struct WebtransportStream {
    receiver: web_transport::RecvStream,
    sender: web_transport::SendStream,
}

impl WebtransportStream {
    pub fn new(sender: web_transport::SendStream, receiver: web_transport::RecvStream) -> Self {
        WebtransportStream { receiver, sender }
    }
}

impl AsyncRead for WebtransportStream {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.receiver.read(buf.len()).await {
            Ok(Some(bytes)) => {
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Ok(None) => Ok(0),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

impl AsyncWrite for WebtransportStream {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sender.write(buf).await {
            Ok(()) => Ok(buf.len()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}
