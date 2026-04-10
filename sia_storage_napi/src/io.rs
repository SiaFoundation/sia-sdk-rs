use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Adapts a JS readable callback into an AsyncRead.
///
/// The callback should return a Buffer on each call, or an empty
/// buffer to signal EOF.
pub(crate) struct JsReader {
    read_fn: ThreadsafeFunction<(), ErrorStrategy::CalleeHandled>,
    pending: Option<BoxFuture<Result<Buffer>>>,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl JsReader {
    pub fn new(read_fn: ThreadsafeFunction<(), ErrorStrategy::CalleeHandled>) -> Self {
        Self {
            read_fn,
            pending: None,
            buf: Vec::new(),
            pos: 0,
            done: false,
        }
    }
}

impl AsyncRead for JsReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.done {
            return Poll::Ready(Ok(()));
        }

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
            let read_fn = this.read_fn.clone();
            this.pending = Some(Box::pin(async move { read_fn.call_async(Ok(())).await }));
        }

        // poll the pending read
        let result = ready!(this.pending.as_mut().unwrap().as_mut().poll(cx));
        this.pending = None;

        match result {
            Ok(data) if data.is_empty() => {
                this.done = true;
                Poll::Ready(Ok(()))
            }
            Ok(data) => {
                let data = data.to_vec();
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.buf = data;
                    this.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Err(e) => {
                this.done = true;
                Poll::Ready(Err(io::Error::other(e.reason)))
            }
        }
    }
}

/// Adapts a JS writable callback into an AsyncWrite.
///
/// The callback receives a Buffer on each write call.
pub(crate) struct JsWriter {
    write_fn: ThreadsafeFunction<Buffer, ErrorStrategy::CalleeHandled>,
    pending: Option<BoxFuture<Result<()>>>,
}

impl JsWriter {
    pub fn new(write_fn: ThreadsafeFunction<Buffer, ErrorStrategy::CalleeHandled>) -> Self {
        Self {
            write_fn,
            pending: None,
        }
    }
}

impl AsyncWrite for JsWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // finish any pending write first (backpressure)
        if let Some(fut) = this.pending.as_mut() {
            match ready!(fut.as_mut().poll(cx)) {
                Ok(()) => this.pending = None,
                Err(e) => {
                    this.pending = None;
                    return Poll::Ready(Err(io::Error::other(e.reason)));
                }
            }
        }

        let n = buf.len();
        let data = Buffer::from(buf.to_vec());
        let write_fn = this.write_fn.clone();
        this.pending = Some(Box::pin(async move { write_fn.call_async(Ok(data)).await }));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(fut) = this.pending.as_mut() {
            match ready!(fut.as_mut().poll(cx)) {
                Ok(()) => this.pending = None,
                Err(e) => {
                    this.pending = None;
                    return Poll::Ready(Err(io::Error::other(e.reason)));
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
