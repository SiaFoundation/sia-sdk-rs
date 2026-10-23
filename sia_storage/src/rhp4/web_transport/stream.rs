use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use js_sys::Uint8Array;
use sia_core::signing::PublicKey;
use tokio::io::{AsyncRead, ReadBuf};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::js_err_message;
use crate::client::Metrics;
use crate::rhp4::Error;
use crate::time::{Duration, Instant, sleep, timeout};

#[wasm_bindgen]
extern "C" {
    type ReadableStreamReadResult;

    #[wasm_bindgen(method, getter, js_name = "done")]
    fn is_done(this: &ReadableStreamReadResult) -> bool;

    #[wasm_bindgen(method, getter)]
    fn value(this: &ReadableStreamReadResult) -> JsValue;
}

/// Timeout for opening a bidirectional stream on an established connection.
/// The RPC's idle clock only starts once the stream is open, so a hung
/// `create_bidirectional_stream` needs its own bound.
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

const WRITE_CHUNK_SIZE: usize = 64 * 1024;

/// Waits for a `createBidirectionalStream` promise and wraps the result.
pub(super) async fn open_bidi_stream(
    promise: js_sys::Promise<web_sys::WebTransportBidirectionalStream>,
    metrics: Arc<Metrics>,
    host: PublicKey,
) -> Result<Stream, Error> {
    let mut pending = PendingStream(Some(promise.clone()));
    let bidi: web_sys::WebTransportBidirectionalStream =
        timeout(OPEN_STREAM_TIMEOUT, JsFuture::from(promise))
            .await
            .map_err(|_| Error::Transport("createBidirectionalStream: timeout".into()))?
            .map_err(|e| {
                Error::Transport(format!("createBidirectionalStream: {}", js_err_message(&e)))
            })?
            .unchecked_into();
    let stream = Stream::new(
        bidi.readable().unchecked_into(),
        bidi.writable().unchecked_into(),
        metrics,
        host,
    )
    .map_err(|e| Error::Transport(format!("get_writer: {}", js_err_message(&e))))?;
    pending.0 = None;
    Ok(stream)
}

/// Closes a stream whose open was abandoned. Without this, a stream that
/// resolves after a timeout or a cancelled read stays open on the session.
struct PendingStream(Option<js_sys::Promise<web_sys::WebTransportBidirectionalStream>>);

impl Drop for PendingStream {
    fn drop(&mut self) {
        let Some(promise) = self.0.take() else {
            return;
        };
        wasm_bindgen_futures::spawn_local(async move {
            let Ok(bidi) = JsFuture::from(promise).await else {
                return;
            };
            let write = JsFuture::from(bidi.writable().abort());
            let read = JsFuture::from(bidi.readable().cancel());
            let _ = tokio::join!(write, read);
        });
    }
}

// --- Stream ---

/// Payload bytes and accumulated active I/O time.
#[derive(Default)]
struct StreamMetric {
    bytes: u64,
    elapsed: Duration,
    start: Option<Instant>,
}

impl StreamMetric {
    fn start(&mut self, now: Instant) {
        self.start = Some(now);
    }

    fn start_if_idle(&mut self) {
        self.start.get_or_insert_with(Instant::now);
    }

    fn record(&mut self, bytes: usize, now: Instant) {
        if bytes == 0 {
            return;
        }
        self.bytes += bytes as u64;
        self.stop(now);
    }

    fn stop(&mut self, now: Instant) {
        if let Some(start) = self.start.take() {
            self.elapsed += now.duration_since(start);
        }
    }

    fn sample(&self) -> (u64, Duration) {
        (
            self.bytes,
            self.elapsed + self.start.map_or(Duration::ZERO, |start| start.elapsed()),
        )
    }
}

/// One bidirectional stream carrying a single RPC. Reads go through
/// [`AsyncRead`]; writes await bounded browser writes via [`Stream::write_chunks`].
pub(super) struct Stream {
    metrics: Arc<Metrics>,
    host: PublicKey,
    reader: web_sys::ReadableStreamDefaultReader,
    pending_read: Option<JsFuture>,
    /// Unread tail of the last chunk from `reader`, as a view into the JS
    /// chunk rather than a copy.
    leftover: Option<Uint8Array>,
    writer: web_sys::WritableStreamDefaultWriter,
    last_progress: Instant,
    read_metric: StreamMetric,
    write_metric: StreamMetric,
    idle_timeout: Duration,
    idle_timer: Option<Pin<Box<dyn Future<Output = ()>>>>,
    timed_out: bool,
}

impl Stream {
    pub(super) async fn run<T>(
        mut self,
        rpc: impl AsyncFnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let result = rpc(&mut self).await;
        self.metrics.record_result(self.host, result)
    }

    /// Received payload bytes and accumulated time waiting for chunks.
    pub(super) fn read_metric(&self) -> (u64, Duration) {
        self.read_metric.sample()
    }

    /// Browser-accepted payload bytes and accumulated time awaiting writes.
    pub(super) fn write_metric(&self) -> (u64, Duration) {
        self.write_metric.sample()
    }

    fn new(
        readable: web_sys::ReadableStream,
        writable: web_sys::WritableStream,
        metrics: Arc<Metrics>,
        host: PublicKey,
    ) -> Result<Self, JsValue> {
        let reader = readable.get_reader().unchecked_into();
        let writer = writable.get_writer()?;
        Ok(Self {
            metrics,
            host,
            reader,
            pending_read: None,
            leftover: None,
            writer,
            last_progress: Instant::now(),
            read_metric: StreamMetric::default(),
            write_metric: StreamMetric::default(),
            idle_timeout: crate::rhp4::RPC_IDLE_TIMEOUT,
            idle_timer: None,
            timed_out: false,
        })
    }

    fn idle_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "WebTransport stream idle")
    }

    fn poll_idle(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.timed_out {
            return Poll::Ready(Err(Self::idle_error()));
        }
        let limit = self.idle_timeout;
        loop {
            let elapsed = self.last_progress.elapsed();
            if elapsed >= limit {
                self.timed_out = true;
                let now = Instant::now();
                self.read_metric.stop(now);
                self.write_metric.stop(now);
                return Poll::Ready(Err(Self::idle_error()));
            }
            let timer = self
                .idle_timer
                .get_or_insert_with(|| Box::pin(sleep(limit - elapsed)));
            std::task::ready!(timer.as_mut().poll(cx));
            // Progress may have moved the deadline since this timer was armed.
            self.idle_timer = None;
        }
    }

    /// Await each bounded write so browser backpressure exposes incremental
    /// progress. Completion indicates browser acceptance rather than transport
    /// ack.
    pub(super) async fn write_chunks(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        if self.timed_out {
            return Err(Self::idle_error());
        }
        for chunk in data.chunks(WRITE_CHUNK_SIZE) {
            let array = Uint8Array::new_with_length(chunk.len() as u32);
            array.copy_from(chunk);
            self.write_metric.start(Instant::now());
            let mut write = JsFuture::from(self.writer.write_with_chunk(&array));
            let result = poll_fn(|cx| match Pin::new(&mut write).poll(cx) {
                Poll::Ready(result) => Poll::Ready(
                    result
                        .map(|_| ())
                        .map_err(|e| std::io::Error::other(js_err_message(&e))),
                ),
                Poll::Pending => self.poll_idle(cx),
            })
            .await;
            if let Err(err) = result {
                self.write_metric.stop(Instant::now());
                return Err(err);
            }
            self.last_progress = Instant::now();
            self.write_metric.record(chunk.len(), self.last_progress);
        }
        Ok(())
    }
}

/// Explicitly close both halves of the bidirectional stream when dropped.
/// Without this, the browser holds the underlying transport resources
/// alive until the JS stream wrappers are garbage-collected
impl Drop for Stream {
    fn drop(&mut self) {
        let reader = self.reader.clone();
        let writer = self.writer.clone();
        let timed_out = self.timed_out;
        wasm_bindgen_futures::spawn_local(async move {
            let write = JsFuture::from(if timed_out {
                writer.abort()
            } else {
                writer.close()
            });
            let read = JsFuture::from(reader.cancel());
            let _ = tokio::join!(write, read);
        });
    }
}

/// Copies as much of `chunk` as fits into `buf`, straight from JS memory,
/// and returns the unread tail as a view into the same chunk.
fn fill_from_chunk(chunk: Uint8Array, buf: &mut ReadBuf<'_>) -> Option<Uint8Array> {
    let len = chunk.length();
    let n = len.min(buf.remaining() as u32);
    chunk
        .subarray(0, n)
        .copy_to(buf.initialize_unfilled_to(n as usize));
    buf.advance(n as usize);
    (n < len).then(|| chunk.subarray(n, len))
}

/// AsyncRead for reading RPC responses. The JS `reader.read()` returns
/// large chunks naturally; whatever the caller's buffer cannot take is kept
/// in `self.leftover` for the next poll.
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(Self::idle_error()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if let Some(chunk) = this.leftover.take() {
            this.leftover = fill_from_chunk(chunk, buf);
            return Poll::Ready(Ok(()));
        }

        if this.pending_read.is_none() {
            this.read_metric.start_if_idle();
            this.pending_read = Some(JsFuture::from(this.reader.read()));
        }

        let future = this.pending_read.as_mut().unwrap();
        let result = match Pin::new(future).poll(cx) {
            Poll::Ready(Ok(result)) => result,
            Poll::Ready(Err(err)) => {
                this.read_metric.stop(Instant::now());
                return Poll::Ready(Err(std::io::Error::other(js_err_message(&err))));
            }
            Poll::Pending => {
                return this.poll_idle(cx);
            }
        };
        this.pending_read = None;

        let chunk: ReadableStreamReadResult = result.unchecked_into();
        if chunk.is_done() {
            this.read_metric.stop(Instant::now());
            return Poll::Ready(Ok(()));
        }

        let chunk = Uint8Array::new(&chunk.value());
        if chunk.length() == 0 {
            cx.waker().wake_by_ref();
            return this.poll_idle(cx);
        }
        this.last_progress = Instant::now();
        this.read_metric
            .record(chunk.length() as usize, this.last_progress);
        this.leftover = fill_from_chunk(chunk, buf);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::metrics::TransferRate;
    use crate::rhp4::RecordTransfer;
    use crate::time::Instant;
    use js_sys::Uint8Array;
    use tokio::io::AsyncReadExt;
    use wasm_bindgen_futures::spawn_local;
    use wasm_bindgen_test::*;

    /// Idle limit for tests that must not time out.
    const IDLE_TIMEOUT: Duration = Duration::from_secs(1);

    /// Creates a Stream backed by separate read/write TransformStreams.
    /// Returns (stream, feeder_for_reads, reader_for_writes).
    fn test_stream(
        idle_timeout: Duration,
    ) -> (
        Stream,
        web_sys::WritableStreamDefaultWriter,
        web_sys::ReadableStreamDefaultReader,
    ) {
        // Read side: feeder → TransformStream → Stream.reader
        let read_ts = web_sys::TransformStream::new().unwrap();
        let feeder = read_ts.writable().get_writer().unwrap();

        // Write side: Stream.writer → TransformStream → out_reader
        let write_ts = web_sys::TransformStream::new().unwrap();
        let out_reader = write_ts
            .readable()
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();

        let mut stream = Stream::new(
            read_ts.readable(),
            write_ts.writable(),
            Arc::new(Metrics::default()),
            PublicKey::new([1; 32]),
        )
        .unwrap();
        stream.idle_timeout = idle_timeout;
        (stream, feeder, out_reader)
    }

    /// Feed data into a WritableStreamDefaultWriter from a spawned microtask.
    /// The write and read proceed as separate tasks on the JS event loop,
    /// avoiding deadlock in single-threaded WASM.
    fn feed_async(feeder: web_sys::WritableStreamDefaultWriter, data: Vec<u8>) {
        spawn_local(async move {
            let array = Uint8Array::new_with_length(data.len() as u32);
            array.copy_from(&data);
            JsFuture::from(feeder.write_with_chunk(&array))
                .await
                .unwrap();
        });
    }

    #[wasm_bindgen_test]
    async fn control_traffic_does_not_change_transfer_averages() {
        let host = PublicKey::new([1; 32]);
        let rate = TransferRate::try_new(4 * 1024 * 1024, Duration::from_secs(1));
        for (read, write) in [(false, false), (true, false), (false, true)] {
            let metrics = Arc::new(Metrics::default());
            metrics.record_transfer(host, rate, rate);
            for _ in 0..20 {
                let (mut stream, feeder, out_reader) = test_stream(IDLE_TIMEOUT);
                stream.metrics = metrics.clone();
                let rpc = stream.run(async |stream| {
                    let tracked = RecordTransfer {
                        stream,
                        record: |stream: &Stream| {
                            let (read_bytes, read_elapsed) = stream.read_metric();
                            let (write_bytes, write_elapsed) = stream.write_metric();
                            metrics.record_transfer(
                                host,
                                TransferRate::try_new(read_bytes, read_elapsed).filter(|_| read),
                                TransferRate::try_new(write_bytes, write_elapsed).filter(|_| write),
                            );
                        },
                    };
                    let stream = &mut *tracked.stream;
                    stream.write_chunks(b"request").await?;
                    stream.read_exact(&mut [0; 3]).await?;
                    assert_eq!(stream.read_metric().0, 3);
                    assert_eq!(stream.write_metric().0, 7);
                    assert!(!stream.read_metric().1.is_zero());
                    assert!(!stream.write_metric().1.is_zero());
                    Ok(())
                });
                let peer = async {
                    sleep(Duration::from_millis(10)).await;
                    JsFuture::from(out_reader.read()).await.unwrap();
                    sleep(Duration::from_millis(10)).await;
                    let ack = Uint8Array::from(b"ack".as_slice());
                    JsFuture::from(feeder.write_with_chunk(&ack)).await.unwrap();
                };
                let (result, ()) = tokio::join!(rpc, peer);
                result.unwrap();
            }
            let rates = metrics.transfer_rates();
            assert_eq!(rates.read != rate, read);
            assert_eq!(rates.write != rate, write);
        }
    }

    #[wasm_bindgen_test]
    async fn partial_read_metrics_survive_cancellation() {
        let (stream, feeder, _out_reader) = test_stream(IDLE_TIMEOUT);
        let metrics = stream.metrics.clone();
        spawn_local(async move {
            sleep(Duration::from_millis(10)).await;
            feed_async(feeder, b"a".to_vec());
        });
        let host = stream.host;
        metrics.record_result(host, Ok(())).unwrap();
        let read = stream.run(async |stream| {
            let tracked = RecordTransfer {
                stream,
                record: |stream: &Stream| {
                    let (bytes, elapsed) = stream.read_metric();
                    metrics.record_transfer(host, TransferRate::try_new(bytes, elapsed), None);
                },
            };
            let stream = &mut *tracked.stream;
            stream.read_exact(&mut [0; 2]).await?;
            Ok(())
        });
        assert!(timeout(Duration::from_millis(50), read).await.is_err());
        assert!(
            metrics.transfer_rates().read.unwrap()
                <= crate::client::metrics::Transfer::new(1, Duration::from_millis(40)).rate()
        );
        assert!(metrics.transfer_rates().write.is_none());
        assert_eq!(metrics.failure_rate(host), 0);
    }

    #[wasm_bindgen_test]
    async fn run_records_each_outcome_once() {
        let metrics = Arc::new(Metrics::default());
        let host = PublicKey::new([1; 32]);
        for (result, expected_rate) in [
            (Err(Error::Transport("failed".into())), 100),
            (Ok(()), 80),
            (Err(Error::NoToken(host)), 80),
        ] {
            let (mut stream, _feeder, _out_reader) = test_stream(IDLE_TIMEOUT);
            stream.metrics = metrics.clone();
            let success = result.is_ok();
            assert_eq!(stream.run(async |_| result).await.is_ok(), success);
            assert_eq!(metrics.failure_rate(host), expected_rate);
        }
    }

    #[wasm_bindgen_test]
    async fn test_stream_write_basic() {
        let (mut stream, _, out_reader) = test_stream(IDLE_TIMEOUT);

        // Write from a spawned task — even with separate TransformStreams,
        // the write-side transform won't pull unless the readable side is
        // being consumed. Spawning lets the read and write interleave.
        let data = b"hello from rust";
        let data_clone = data.to_vec();
        spawn_local(async move {
            stream.write_chunks(&data_clone).await.unwrap();
        });

        let result = JsFuture::from(out_reader.read()).await.unwrap();
        let chunk: ReadableStreamReadResult = result.unchecked_into();
        assert!(!chunk.is_done());
        let received = Uint8Array::new(&chunk.value()).to_vec();
        assert_eq!(received, data);
    }

    #[wasm_bindgen_test]
    async fn test_stream_write_large() {
        let (mut stream, _, out_reader) = test_stream(IDLE_TIMEOUT);

        let data = vec![0xABu8; WRITE_CHUNK_SIZE * 2 + 17];
        let data_clone = data.clone();
        spawn_local(async move {
            stream.write_chunks(&data_clone).await.unwrap();
        });

        let mut received = Vec::new();
        while received.len() < data.len() {
            let result = JsFuture::from(out_reader.read()).await.unwrap();
            let chunk: ReadableStreamReadResult = result.unchecked_into();
            assert!(!chunk.is_done());
            let chunk = Uint8Array::new(&chunk.value());
            assert!(chunk.length() as usize <= WRITE_CHUNK_SIZE);
            received.extend_from_slice(&chunk.to_vec());
        }
        assert_eq!(received, data);
    }

    #[wasm_bindgen_test]
    async fn test_stalled_read_times_out_and_stays_failed() {
        let (mut stream, _feeder, _out_reader) = test_stream(Duration::from_millis(25));
        let err = timeout(Duration::from_secs(1), stream.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        stream.leftover = Some(Uint8Array::from(&b"buffered"[..]));
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write_chunks(b"retry").await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[wasm_bindgen_test]
    async fn test_stalled_write_times_out_and_stays_failed() {
        let (mut stream, _feeder, out_reader) = test_stream(Duration::from_millis(25));
        let err = timeout(Duration::from_secs(1), stream.write_chunks(b"blocked"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write_chunks(b"retry").await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(stream);
        // Cleanup must abort the pending write instead of queuing close behind it.
        assert!(
            timeout(Duration::from_secs(1), JsFuture::from(out_reader.read()))
                .await
                .unwrap()
                .is_err()
        );
    }

    #[wasm_bindgen_test]
    async fn test_read_progress_resets_idle_but_buffered_reads_do_not() {
        let (mut stream, feeder, _out_reader) = test_stream(IDLE_TIMEOUT);
        assert_eq!(stream.read_metric(), (0, Duration::ZERO));
        assert_eq!(stream.write_metric(), (0, Duration::ZERO));
        let old = stream.last_progress;
        sleep(Duration::from_millis(5)).await;
        feed_async(feeder, b"ab".to_vec());
        assert_eq!(stream.read_u8().await.unwrap(), b'a');
        let metric = stream.read_metric();
        assert_eq!(metric.0, 2);
        let progress = stream.last_progress;
        assert!(progress > old);
        assert_eq!(stream.read_u8().await.unwrap(), b'b');
        assert_eq!(stream.last_progress, progress);
        assert_eq!(stream.read_metric(), metric);
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        let timed_out = stream.read_metric();
        assert_eq!(timed_out.0, metric.0);
        assert!(timed_out.1 > metric.1);
        assert!(timed_out.1 >= IDLE_TIMEOUT / 2);
        sleep(Duration::from_millis(10)).await;
        assert_eq!(stream.read_metric(), timed_out);
    }

    /// A transfer that outlasts the idle limit must still succeed as long as
    /// every chunk lands within it. The reader paces the writer: with a zero
    /// high-water mark, each chunk's write only resolves once it is pulled.
    #[wasm_bindgen_test]
    async fn test_slow_but_progressing_write_outlasts_idle_limit() {
        const LIMIT: Duration = Duration::from_millis(200);
        const GAP: Duration = Duration::from_millis(100);
        const CHUNKS: usize = 4;
        let (mut stream, _feeder, out_reader) = test_stream(LIMIT);
        let data = vec![42; WRITE_CHUNK_SIZE * CHUNKS];
        let (tx, rx) = tokio::sync::oneshot::channel();
        spawn_local(async move {
            tx.send(stream.write_chunks(&data).await).unwrap();
        });
        let start = Instant::now();
        for _ in 0..CHUNKS {
            sleep(GAP).await;
            let result = JsFuture::from(out_reader.read()).await.unwrap();
            let chunk: ReadableStreamReadResult = result.unchecked_into();
            assert_eq!(
                Uint8Array::new(&chunk.value()).length() as usize,
                WRITE_CHUNK_SIZE
            );
        }
        assert!(
            start.elapsed() > LIMIT,
            "the transfer must outlast the idle limit"
        );
        rx.await.unwrap().unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_write_metric_preserves_completed_chunks_on_timeout() {
        let (mut stream, _feeder, out_reader) = test_stream(Duration::from_millis(100));
        let (tx, rx) = tokio::sync::oneshot::channel();
        spawn_local(async move {
            let result = stream.write_chunks(&vec![42; WRITE_CHUNK_SIZE * 2]).await;
            tx.send((result, stream.write_metric())).unwrap();
        });
        sleep(Duration::from_millis(10)).await;
        JsFuture::from(out_reader.read()).await.unwrap();
        let (result, (bytes, elapsed)) = rx.await.unwrap();
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(bytes, WRITE_CHUNK_SIZE as u64);
        assert!(elapsed >= Duration::from_millis(100));
    }

    #[wasm_bindgen_test]
    async fn test_metrics_exclude_gaps_between_operations() {
        let (mut stream, feeder, out_reader) = test_stream(IDLE_TIMEOUT);
        let mut read_time = Duration::ZERO;
        let mut write_time = Duration::ZERO;
        for bytes in 1..=2 {
            sleep(Duration::from_millis(100)).await;
            let start = Instant::now();
            feed_async(feeder.clone(), b"a".to_vec());
            assert_eq!(stream.read_u8().await.unwrap(), b'a');
            read_time += start.elapsed();
            assert_eq!(stream.read_metric().0, bytes);
            assert!(stream.read_metric().1 <= read_time);

            sleep(Duration::from_millis(100)).await;
            let start = Instant::now();
            let (tx, rx) = tokio::sync::oneshot::channel();
            spawn_local(async move {
                stream.write_chunks(b"b").await.unwrap();
                tx.send(stream).ok().unwrap();
            });
            JsFuture::from(out_reader.read()).await.unwrap();
            stream = rx.await.unwrap();
            write_time += start.elapsed();
            assert_eq!(stream.write_metric().0, bytes);
            assert!(stream.write_metric().1 <= write_time);
        }
    }

    #[wasm_bindgen_test]
    async fn test_stream_read_exact() {
        let (mut stream, feeder, _) = test_stream(IDLE_TIMEOUT);
        feed_async(feeder, b"hello, world!".to_vec());

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let mut buf = vec![0u8; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b", world!");
    }

    #[wasm_bindgen_test]
    async fn test_stream_read_buffering() {
        let (mut stream, feeder, _) = test_stream(IDLE_TIMEOUT);
        feed_async(feeder, vec![42u8; 1024]);

        let mut total = Vec::new();
        for _ in 0..4 {
            let mut buf = vec![0u8; 256];
            stream.read_exact(&mut buf).await.unwrap();
            total.extend_from_slice(&buf);
        }
        assert_eq!(total, vec![42u8; 1024]);
    }

    #[wasm_bindgen_test]
    async fn test_stream_roundtrip() {
        // Use two separate TransformStreams: one for write, one for read.
        // Write side: our Stream writes → write_ts → out_reader verifies
        // Read side: feeder feeds → read_ts → our Stream reads
        let (mut stream, feeder, out_reader) = test_stream(IDLE_TIMEOUT);

        let data = b"roundtrip test data!";

        // 1. Feed data into the read side and read it through our Stream
        feed_async(feeder, data.to_vec());
        let mut buf = vec![0u8; data.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, data);

        // 2. Write data through our Stream and verify it on the write side
        let data_vec = data.to_vec();
        spawn_local(async move {
            stream.write_chunks(&data_vec).await.unwrap();
        });
        let result = JsFuture::from(out_reader.read()).await.unwrap();
        let chunk: ReadableStreamReadResult = result.unchecked_into();
        assert!(!chunk.is_done());
        let received = Uint8Array::new(&chunk.value()).to_vec();
        assert_eq!(received, data);
    }

    #[wasm_bindgen_test]
    async fn test_stream_read_multiple_feeds() {
        let (mut stream, feeder, _) = test_stream(IDLE_TIMEOUT);

        spawn_local(async move {
            let array = Uint8Array::new_with_length(5);
            array.copy_from(b"hello");
            JsFuture::from(feeder.write_with_chunk(&array))
                .await
                .unwrap();

            let array = Uint8Array::new_with_length(5);
            array.copy_from(b"world");
            JsFuture::from(feeder.write_with_chunk(&array))
                .await
                .unwrap();
        });

        let mut buf = vec![0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"helloworld");
    }

    /// Returns a stand-in for a `WebTransportBidirectionalStream` with the
    /// feeder for its readable and the reader for its writable.
    fn bidi_fixture() -> (
        JsValue,
        web_sys::WritableStreamDefaultWriter,
        web_sys::ReadableStreamDefaultReader,
    ) {
        let read_ts = web_sys::TransformStream::new().unwrap();
        let write_ts = web_sys::TransformStream::new().unwrap();
        let bidi = js_sys::Object::new();
        js_sys::Reflect::set(&bidi, &"readable".into(), &read_ts.readable()).unwrap();
        js_sys::Reflect::set(&bidi, &"writable".into(), &write_ts.writable()).unwrap();
        let feeder = read_ts.writable().get_writer().unwrap();
        let out_reader = write_ts
            .readable()
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        (bidi.into(), feeder, out_reader)
    }

    /// Returns a promise that resolves to `bidi` once the sender fires.
    fn deferred(
        bidi: JsValue,
    ) -> (
        js_sys::Promise<web_sys::WebTransportBidirectionalStream>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let promise = wasm_bindgen_futures::future_to_promise(async move {
            let _ = rx.await;
            Ok(bidi)
        });
        (promise.unchecked_into(), tx)
    }

    #[wasm_bindgen_test]
    async fn test_abandoned_open_closes_late_stream() {
        let (bidi, feeder, out_reader) = bidi_fixture();
        let (promise, resolve) = deferred(bidi);
        assert!(
            timeout(
                Duration::from_millis(10),
                open_bidi_stream(
                    promise,
                    Arc::new(Metrics::default()),
                    PublicKey::new([1; 32])
                )
            )
            .await
            .is_err()
        );
        resolve.send(()).unwrap();

        // Cancelling the readable errors its feeder; aborting the writable
        // errors its reader.
        assert!(
            timeout(Duration::from_secs(1), JsFuture::from(feeder.closed()))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            timeout(Duration::from_secs(1), JsFuture::from(out_reader.closed()))
                .await
                .unwrap()
                .is_err()
        );
    }

    #[wasm_bindgen_test]
    async fn test_successful_open_keeps_stream() {
        let (bidi, feeder, out_reader) = bidi_fixture();
        let (promise, resolve) = deferred(bidi);
        resolve.send(()).unwrap();
        let mut stream = open_bidi_stream(
            promise,
            Arc::new(Metrics::default()),
            PublicKey::new([1; 32]),
        )
        .await
        .unwrap();
        stream.idle_timeout = IDLE_TIMEOUT;
        // Give a wrongly armed cleanup time to run.
        sleep(Duration::from_millis(50)).await;

        feed_async(feeder, b"ping".to_vec());
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        spawn_local(async move {
            stream.write_chunks(b"pong").await.unwrap();
        });
        let result = JsFuture::from(out_reader.read()).await.unwrap();
        let chunk: ReadableStreamReadResult = result.unchecked_into();
        assert_eq!(Uint8Array::new(&chunk.value()).to_vec(), b"pong");
    }
}
