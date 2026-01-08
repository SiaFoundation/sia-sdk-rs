use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::spawn;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;
use tokio_util::sync::PollSender;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum IOError {
    #[error("i/o error: {0}")]
    Io(String),

    #[error("reader closed")]
    Closed,

    #[error("cancelled")]
    Cancelled,
}

impl From<IOError> for std::io::Error {
    fn from(e: IOError) -> Self {
        match e {
            IOError::Closed => std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e),
            IOError::Cancelled => std::io::Error::new(std::io::ErrorKind::Interrupted, e),
            IOError::Io(msg) => std::io::Error::other(msg),
        }
    }
}

/// A foreign reader that can be used to transfer data across FFI boundaries.
///
/// Implementations should send an empty chunk to signal completion. It is recommended
/// that implementations chunk data into reasonably sized pieces (e.g. 64KiB) to avoid
/// excessive memory usage.
///
/// If an error is returned by `read`, the reader will be closed and no
/// further calls will be made.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait Reader: Send + Sync {
    async fn read(&self) -> Result<Vec<u8>, IOError>;
}

pub(crate) fn adapt_ffi_reader(reader: Arc<dyn Reader>) -> impl AsyncRead + Unpin {
    let (tx, rx) = mpsc::channel(1);

    // Spawn a task to pump data from foreign -> channel
    tokio::spawn(async move {
        loop {
            match reader.read().await {
                Ok(data) if data.is_empty() => return,
                Ok(data) => {
                    if tx.send(Ok(Bytes::from(data))).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });

    StreamReader::new(ReceiverStream::new(rx))
}

/// A foreign writer that can be used to transfer data across FFI boundaries.
/// The data may be sent in multiple chunks. The implementation should handle
/// buffering and writing the data as it is received.
///
/// Implementations should treat a call to `write` with an empty chunk as EoF.
/// If an error is returned by `write`, the writer will be closed and no further
/// calls will be made.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait Write: Send + Sync {
    async fn write(&self, data: Vec<u8>) -> Result<(), IOError>;
}

#[derive(Clone)]
pub struct FFIWriter {
    sender: PollSender<Bytes>,
}

impl AsyncWrite for FFIWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if ready!(this.sender.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            )));
        }

        let n = buf.len();
        let item = Bytes::copy_from_slice(buf);

        if this.sender.send_item(item).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            )));
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().sender.close();
        Poll::Ready(Ok(()))
    }
}

pub(crate) fn adapt_ffi_writer(writer: Arc<dyn Write>) -> FFIWriter {
    let (tx, mut rx) = mpsc::channel::<Bytes>(8);
    spawn(async move {
        while let Some(buf) = rx.recv().await {
            if writer.write(buf.to_vec()).await.is_err() {
                return;
            }
        }
        let _ = writer.write(vec![]).await; // signal EOF
    });
    FFIWriter {
        sender: PollSender::new(tx),
    }
}
