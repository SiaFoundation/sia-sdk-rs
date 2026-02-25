pub mod frame;
pub mod handshake;
pub mod mux;

use std::io;
use std::sync::LazyLock;
use thiserror::Error;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::handshake::{ConnSettings, HandshakeError, accept_handshake, initiate_handshake};
use crate::mux::{Mux, new_mux};

// Re-export key public types.
pub use crate::mux::{MuxError, Stream};

const OUR_VERSION: u8 = 3;

/// Minimum peer version we accept.
const MIN_VERSION: u8 = 3;

/// Anonymous Ed25519 signing key (derived from all-zero seed).
static ANON_SIGNING_KEY: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::from_bytes(&[0u8; 32]));

/// Anonymous Ed25519 verifying key (corresponding to the anonymous signing key).
static ANON_VERIFYING_KEY: LazyLock<VerifyingKey> =
    LazyLock::new(|| ANON_SIGNING_KEY.verifying_key());

#[derive(Debug, Error)]
pub enum DialError {
    #[error("failed to write our version to peer: {0}")]
    WriteVersion(io::Error),
    #[error("failed to read peer version: {0}")]
    ReadVersion(io::Error),
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("invalid peer version: {0}")]
    PeerVersion(u8),
}

fn validate_peer_version(v: u8) -> Result<(), DialError> {
    if v < MIN_VERSION {
        return Err(DialError::PeerVersion(v));
    }
    Ok(())
}

/// Perform the mux handshake as the initiating (dialing) peer.
pub async fn dial<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: T,
    their_key: &VerifyingKey,
) -> Result<Mux, DialError> {
    // Version exchange: dialer writes first, then reads.
    conn.write_u8(OUR_VERSION)
        .await
        .map_err(DialError::WriteVersion)?;
    let their_version = conn.read_u8().await.map_err(DialError::ReadVersion)?;
    validate_peer_version(their_version)?;

    let settings = ConnSettings::default();
    let (cipher, merged) = initiate_handshake(&mut conn, their_key, settings).await?;
    Ok(new_mux(conn, cipher, merged, 0))
}

/// Perform the mux handshake as the accepting (listening) peer.
pub async fn accept<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: T,
    our_key: &SigningKey,
) -> Result<Mux, DialError> {
    // Version exchange: acceptor reads first, then writes.
    let their_version = conn.read_u8().await.map_err(DialError::ReadVersion)?;
    validate_peer_version(their_version)?;
    conn.write_u8(OUR_VERSION)
        .await
        .map_err(DialError::WriteVersion)?;

    let settings = ConnSettings::default();
    let (cipher, merged) = accept_handshake(&mut conn, our_key, settings).await?;
    // Acceptor uses odd stream IDs to avoid collisions with dialer
    Ok(new_mux(conn, cipher, merged, 1))
}

/// Dial without identity verification (anonymous mode).
/// The counterparty must reciprocate with [`accept_anonymous`].
pub async fn dial_anonymous<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
) -> Result<Mux, DialError> {
    dial(conn, &ANON_VERIFYING_KEY).await
}

/// Accept without identity verification (anonymous mode).
/// The counterparty must initiate with [`dial_anonymous`].
pub async fn accept_anonymous<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
) -> Result<Mux, DialError> {
    accept(conn, &ANON_SIGNING_KEY).await
}
