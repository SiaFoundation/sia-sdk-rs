use std::pin::Pin;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    runtime::Runtime,
};
use wtransport::{ClientConfig, Endpoint};

#[tokio::main]
async fn main() {
    let client_config = ClientConfig::default();
    let client = Endpoint::client(client_config).expect("failed to create endpoint");

    let connection = client
        .connect(
            "https://2l8dvkho84abi14l313c4r48267fhffujsbk9hkvproe1rmkhme0.sia.host:9984/sia/rhp/v4",
        )
        .await
        .expect("failed to establish connection");

    let (sender, receiver) = connection.open_bi().await.unwrap().await.unwrap();
    let stream = wtransport::stream::BiStream::join((sender, receiver));
    let stream = BlockingStream { stream };

    let res = sia::rhp::rpc_settings(stream).unwrap();

    println!("result {:?}", res.settings)
}

// BlockingStream wraps an AsyncWrite + AsyncRead stream to provide a blocking interface
struct BlockingStream<S: AsyncWrite + AsyncRead> {
    stream: S,
}

impl<S: AsyncWrite + AsyncRead + Unpin> std::io::Write for BlockingStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut stream = Pin::new(&mut self.stream);
        Runtime::new()
            .unwrap()
            .block_on(stream.write(buf))
            .map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut stream = Pin::new(&mut self.stream);
        Runtime::new()
            .unwrap()
            .block_on(stream.flush())
            .map_err(std::io::Error::other)
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin> std::io::Read for BlockingStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut stream = Pin::new(&mut self.stream);
        Runtime::new()
            .unwrap()
            .block_on(stream.read(buf))
            .map_err(std::io::Error::other)
    }
}
