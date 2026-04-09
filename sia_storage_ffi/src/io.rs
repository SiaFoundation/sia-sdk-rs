use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

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

impl AsyncBufRead for FFIReader {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();

        // return buffered data if available
        if this.pos < this.buf.len() {
            return Poll::Ready(Ok(&this.buf[this.pos..]));
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
            Ok(data) if data.is_empty() => Poll::Ready(Ok(&[])), // EOF
            Ok(data) => {
                this.buf = data;
                this.pos = 0;
                Poll::Ready(Ok(&this.buf))
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        this.pos += amt;
        if this.pos >= this.buf.len() {
            this.buf.clear();
            this.pos = 0;
        }
    }
}

/// A foreign writer that can be used to transfer data across FFI boundaries.
/// The data may be sent in multiple chunks. The implementation should handle
/// buffering and writing the data as it is received.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait Writer: Send + Sync {
    async fn write(&self, data: Vec<u8>) -> Result<(), IOError>;
}

/// Adapts a foreign Writer into an AsyncWrite by polling the write future directly.
pub(crate) struct FFIWriter {
    writer: Arc<dyn Writer>,
    pending: Option<BoxFuture<Result<(), IOError>>>,
}

impl FFIWriter {
    pub fn new(writer: Arc<dyn Writer>) -> Self {
        Self {
            writer,
            pending: None,
        }
    }
}

impl AsyncWrite for FFIWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // finish pending writes first
        if let Some(fut) = this.pending.as_mut() {
            match ready!(fut.as_mut().poll(cx)) {
                Ok(()) => this.pending = None,
                Err(e) => {
                    this.pending = None;
                    return Poll::Ready(Err(e.into()));
                }
            }
        }

        let n = buf.len();
        let writer = this.writer.clone();
        let data = buf.to_vec();
        this.pending = Some(Box::pin(async move { writer.write(data).await }));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(fut) = this.pending.as_mut() {
            match ready!(fut.as_mut().poll(cx)) {
                Ok(()) => this.pending = None,
                Err(e) => {
                    this.pending = None;
                    return Poll::Ready(Err(e.into()));
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[derive(Debug)]
    struct VecWriter {
        data: Mutex<Vec<u8>>,
    }

    impl VecWriter {
        fn new() -> Self {
            Self {
                data: Mutex::new(Vec::new()),
            }
        }

        fn into_inner(self) -> Vec<u8> {
            self.data.into_inner().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl Writer for VecWriter {
        async fn write(&self, data: Vec<u8>) -> Result<(), IOError> {
            self.data.lock().unwrap().extend_from_slice(&data);
            Ok(())
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

    #[tokio::test]
    async fn test_ffi_writer() {
        let input: Vec<u8> = (0..=255).cycle().take(CHUNK_SIZE * 5 + 17).collect();
        let writer = Arc::new(VecWriter::new());
        let mut w = FFIWriter::new(writer.clone());

        for chunk in input.chunks(CHUNK_SIZE) {
            w.write_all(chunk).await.unwrap();
        }
        w.shutdown().await.unwrap();
        drop(w);

        let output = Arc::try_unwrap(writer).unwrap().into_inner();
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn test_ffi_reader_writer_roundtrip() {
        let input: Vec<u8> = (0..=255).cycle().take(CHUNK_SIZE * 10).collect();

        // read the input through FFIReader
        let reader = Arc::new(VecReader::new(input.clone()));
        let mut r = FFIReader::new(reader);

        // pipe it through FFIWriter
        let writer = Arc::new(VecWriter::new());
        let mut w = FFIWriter::new(writer.clone());

        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n]).await.unwrap();
        }
        w.shutdown().await.unwrap();
        drop(w);

        let output = Arc::try_unwrap(writer).unwrap().into_inner();
        assert_eq!(output, input);
    }
}
