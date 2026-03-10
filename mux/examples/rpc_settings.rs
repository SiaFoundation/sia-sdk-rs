//! Dial a Sia host over TCP, establish a mux connection, and call RPCSettings.
//!
//! Usage:
//!   cargo run -p mux --example rpc_settings -- <host:port> <ed25519:pubkey>
//!   cargo run -p mux --example rpc_settings -- --anonymous <host:port>

use std::env;

use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use mux::{DialError, MuxError};
use sia::encoding::Error as EncodingError;
use sia::encoding_async::AsyncDecoder;
use sia::rhp::{self, RPCRequest, RPCResponse, RPCSettings, Transport};
use sia::signing::PublicKey;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("mux: {0}")]
    Mux(#[from] MuxError),
    #[error("handshake: {0}")]
    Handshake(#[from] mux::handshake::HandshakeError),
    #[error("rhp: {0}")]
    Rhp(#[from] rhp::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding: {0}")]
    Encoding(#[from] EncodingError),
    #[error("dial: {0}")]
    Dial(#[from] DialError),
}

/// Wraps a mux [`Stream`](mux::Stream) to implement [`Transport`].
struct MuxTransport(mux::Stream);

impl AsyncDecoder for MuxTransport {
    type Error = Error;
    async fn decode_buf(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_exact(buf).await?;
        Ok(())
    }
}

impl Transport for MuxTransport {
    type Error = Error;

    async fn write_request<R: RPCRequest>(&mut self, req: &R) -> Result<(), Self::Error> {
        req.encode_request(&mut self.0).await?;
        Ok(())
    }

    async fn write_bytes(&mut self, data: Bytes) -> Result<(), Self::Error> {
        self.0.write_all(&data).await?;
        Ok(())
    }

    async fn read_response<R: RPCResponse>(&mut self) -> Result<R, Self::Error> {
        R::decode_response(self).await
    }

    async fn write_response<RR: RPCResponse>(&mut self, resp: &RR) -> Result<(), Self::Error> {
        resp.encode_response(&mut self.0).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    let (addr, anonymous) = match args.get(1).map(String::as_str) {
        Some("--anonymous") => (
            args.get(2)
                .expect("usage: rpc_settings --anonymous <host:port>")
                .as_str(),
            true,
        ),
        Some(addr) => (addr, false),
        None => {
            eprintln!("usage: rpc_settings [--anonymous] <host:port> [ed25519:pubkey]");
            std::process::exit(1);
        }
    };

    // Connect TCP
    eprintln!("connecting to {addr}...");
    let tcp = TcpStream::connect(addr).await?;

    // Establish mux
    let m = if anonymous {
        eprintln!("performing anonymous mux handshake...");
        mux::dial_anonymous(tcp).await?
    } else {
        let key_str = args.get(2).expect("missing host public key (ed25519:...)");
        let sia_key: PublicKey = key_str.parse().expect("invalid public key format");
        let bytes: [u8; 32] = sia_key.into();
        let vk = VerifyingKey::from_bytes(&bytes).expect("invalid ed25519 key");
        eprintln!("performing mux handshake (verifying host key)...");
        mux::dial(tcp, &vk).await?
    };
    eprintln!("mux established");

    // Open a stream and call RPCSettings
    let stream = m.dial_stream()?;
    let result = RPCSettings::send_request(MuxTransport(stream))
        .await?
        .complete()
        .await?;

    // Print the host settings as JSON
    println!(
        "{}",
        serde_json::to_string_pretty(&result.settings).unwrap()
    );

    m.close().await?;
    Ok(())
}
