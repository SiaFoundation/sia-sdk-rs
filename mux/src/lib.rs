#![allow(dead_code)]

pub mod frame;
pub mod handshake;
pub mod mux;

use std::io;
use std::sync::LazyLock;
use thiserror::Error;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::handshake::{HandshakeError, accept_handshake, initiate_handshake};
use crate::mux::new_mux;

// Re-export key public types.
pub use crate::handshake::{ConnSettings, IPV6_MTU};
pub use crate::mux::{Mux, MuxError, Stream};

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
    conn: T,
    their_key: &VerifyingKey,
) -> Result<Mux, DialError> {
    dial_with_settings(conn, their_key, ConnSettings::default()).await
}

/// Perform the mux handshake as the initiating (dialing) peer with custom settings.
pub async fn dial_with_settings<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: T,
    their_key: &VerifyingKey,
    settings: ConnSettings,
) -> Result<Mux, DialError> {
    conn.write_u8(OUR_VERSION)
        .await
        .map_err(DialError::WriteVersion)?;
    let their_version = conn.read_u8().await.map_err(DialError::ReadVersion)?;
    validate_peer_version(their_version)?;

    let (cipher, merged) = initiate_handshake(&mut conn, their_key, settings).await?;
    Ok(new_mux(conn, cipher, merged, 0))
}

/// Perform the mux handshake as the accepting (listening) peer.
pub async fn accept<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
    our_key: &SigningKey,
) -> Result<Mux, DialError> {
    accept_with_settings(conn, our_key, ConnSettings::default()).await
}

/// Perform the mux handshake as the accepting (listening) peer with custom settings.
pub async fn accept_with_settings<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut conn: T,
    our_key: &SigningKey,
    settings: ConnSettings,
) -> Result<Mux, DialError> {
    let their_version = conn.read_u8().await.map_err(DialError::ReadVersion)?;
    validate_peer_version(their_version)?;
    conn.write_u8(OUR_VERSION)
        .await
        .map_err(DialError::WriteVersion)?;

    let (cipher, merged) = accept_handshake(&mut conn, our_key, settings).await?;
    Ok(new_mux(conn, cipher, merged, 1))
}

/// Dial without identity verification (anonymous mode).
/// The counterparty must reciprocate with [`accept_anonymous`].
pub async fn dial_anonymous<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
) -> Result<Mux, DialError> {
    dial(conn, &ANON_VERIFYING_KEY).await
}

/// Dial without identity verification and with custom settings.
pub async fn dial_anonymous_with_settings<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
    settings: ConnSettings,
) -> Result<Mux, DialError> {
    dial_with_settings(conn, &ANON_VERIFYING_KEY, settings).await
}

/// Accept without identity verification (anonymous mode).
/// The counterparty must initiate with [`dial_anonymous`].
pub async fn accept_anonymous<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
) -> Result<Mux, DialError> {
    accept(conn, &ANON_SIGNING_KEY).await
}

/// Accept without identity verification and with custom settings.
pub async fn accept_anonymous_with_settings<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
    settings: ConnSettings,
) -> Result<Mux, DialError> {
    accept_with_settings(conn, &ANON_SIGNING_KEY, settings).await
}
