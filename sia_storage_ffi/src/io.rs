use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use thiserror::Error;
use tokio::io::{AsyncRead, ReadBuf};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

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

/// Adapts a foreign Reader into an AsyncRead by polling the read future directly.
pub(crate) struct FFIReader {
    reader: Arc<dyn Reader>,
    pending: Option<BoxFuture<Result<Vec<u8>, IOError>>>,
    buf: Vec<u8>,
    pos: usize,
}

impl FFIReader {
    pub fn new(reader: Arc<dyn Reader>) -> Self {
        Self {
            reader,
            pending: None,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for FFIReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // drain buffered data first
        if this.pos < this.buf.len() {
            let n = (this.buf.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.buf[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.buf.len() {
                this.buf.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // start a new read if none is pending
        if this.pending.is_none() {
            let reader = this.reader.clone();
            this.pending = Some(Box::pin(async move { reader.read().await }));
        }

        // poll the pending read
        let result = ready!(this.pending.as_mut().unwrap().as_mut().poll(cx));
        this.pending = None;

        match result {
            Ok(data) if data.is_empty() => Poll::Ready(Ok(())), // EOF
            Ok(data) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.buf = data;
                    this.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;

    const CHUNK_SIZE: usize = 64;

    struct VecReader {
        data: Mutex<Vec<u8>>,
    }

    impl VecReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: Mutex::new(data),
            }
        }
    }

    #[async_trait::async_trait]
    impl Reader for VecReader {
        async fn read(&self) -> Result<Vec<u8>, IOError> {
            let mut data = self.data.lock().unwrap();
            if data.is_empty() {
                return Ok(Vec::new());
            }
            let n = data.len().min(CHUNK_SIZE);
            let chunk = data.drain(..n).collect();
            Ok(chunk)
        }
    }

    #[tokio::test]
    async fn test_ffi_reader() {
        let input: Vec<u8> = (0..=255).cycle().take(CHUNK_SIZE * 5 + 17).collect();
        let reader = Arc::new(VecReader::new(input.clone()));
        let mut r = FFIReader::new(reader);

        let mut output = Vec::new();
        r.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, input);
    }
}
