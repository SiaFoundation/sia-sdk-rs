use std::pin::Pin;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    runtime::Runtime,
};
use web_transport;

#[tokio::main]
async fn main() {
    let client = web_transport::ClientBuilder::default()
        .with_system_roots()
        .unwrap();

    let mut connection = client
        .connect(
            "https://2l8dvkho84abi14l313c4r48267fhffujsbk9hkvproe1rmkhme0.sia.host:9984/sia/rhp/v4"
                .parse()
                .unwrap(),
        )
        .await
        .expect("failed to establish connection");

    let (sender, receiver) = connection.open_bi().await.unwrap();

    //    let res = sia::rhp::rpc_settings(stream).unwrap();

    // println!("result {:?}", res.settings)
}
