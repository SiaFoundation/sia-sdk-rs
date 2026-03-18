use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time;

use crate::frame::{
    FLAG_ERROR, FLAG_FIRST, FLAG_LAST, FRAME_HEADER_SIZE, FrameHeader, ID_KEEPALIVE,
    ID_LOWEST_STREAM, PacketReader, PacketReaderError, PacketWriter, append_frame,
};
use crate::handshake::{ConnSettings, HandshakeResult, SeqCipher};

/// Grace period before removing a closed stream from tracking.
const CLOSING_STREAM_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// After [`Mux::close`], how long to wait for the peer to send EOF before
/// forcibly aborting the read loop. The read loop is detached (not immediately
/// aborted) so the peer can finish reading any frames still buffered in the TCP
/// stack. If the peer never closes, this bounds the resource lifetime.
pub(crate) const READ_LOOP_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum frames to accept for a closed stream before treating it as a flood.
const MAX_CLOSED_FRAMES: u16 = 1000;

/// Maximum concurrent streams.
const MAX_STREAMS: usize = 1 << 20;

/// Write buffer backpressure factor: max buffer size = max_payload_size * this.
const MAX_WRITE_BUF_FACTOR: usize = 10;

/// Errors produced by mux and stream operations.
#[derive(Debug, Clone, Error)]
pub enum MuxError {
    #[error("underlying connection was closed")]
    ClosedConn,
    #[error("stream was gracefully closed")]
    ClosedStream,
    #[error("peer closed stream gracefully")]
    PeerClosedStream,
    #[error("peer closed underlying connection")]
    PeerClosedConn,
    #[error("too many frames received for closed stream")]
    StreamFlood,
    #[error("frame received for unknown stream")]
    UnknownStream,
    #[error("exceeded concurrent stream limit")]
    TooManyStreams,
    #[error("peer sent invalid frame ID: {0}")]
    InvalidFrameId(u32),
    #[error("{0}")]
    Io(String),
    #[error("peer error: {0}")]
    PeerError(String),
}

/// Required because [`AsyncRead`] and [`AsyncWrite`] trait methods return `io::Result`.
impl From<MuxError> for io::Error {
    fn from(e: MuxError) -> Self {
        let kind = match &e {
            MuxError::ClosedConn | MuxError::ClosedStream => io::ErrorKind::ConnectionAborted,
            MuxError::PeerClosedStream | MuxError::PeerClosedConn => io::ErrorKind::ConnectionReset,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

fn is_conn_close_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Checks whether a [`PacketReaderError`] represents a connection closure by
/// inspecting the underlying [`io::Error`] kind directly (rather than
/// round-tripping through a string which loses the kind).
fn packet_reader_error_is_conn_close(err: &PacketReaderError) -> bool {
    match err {
        PacketReaderError::ReadHeader(e) | PacketReaderError::ReadPayload(e) => {
            is_conn_close_error(e)
        }
        _ => false,
    }
}

/// Per-stream read state, protected by its own mutex (separate from the mux lock).
struct StreamState {
    /// Buffered read data delivered by the read loop.
    read_buf: BytesMut,
    /// Sticky error for this stream (peer closed, mux error, etc.).
    err: Option<MuxError>,
    /// Waker for the reader waiting for data.
    waker: Option<Waker>,
}

/// Tracks a recently-closed stream to absorb in-flight frames from the peer.
struct ClosingStreamEntry {
    /// Number of frames received since closure (flood detection).
    frame_count: u16,
    /// When the stream was closed, used for periodic cleanup.
    closed: time::Instant,
}

/// Shared mux state, protected by a single [`StdMutex`].
struct MuxState {
    /// Shared write buffer. Streams append frames directly here; the write loop
    /// swaps it out, encrypts, and writes to the connection.
    write_buf: Vec<u8>,
    /// Wakers for streams blocked due to write buffer backpressure.
    /// Wake-one: write_loop wakes the front; each successful writer
    /// chain-wakes the next.
    buffer_wakers: VecDeque<Waker>,

    /// Active streams indexed by stream ID.
    streams: HashMap<u32, Arc<StdMutex<StreamState>>>,
    /// Recently-closed streams kept around to absorb straggler frames.
    closing: HashMap<u32, ClosingStreamEntry>,

    /// Pending streams waiting for acceptance.
    accept_queue: VecDeque<Stream>,

    /// Notifier for tasks blocked in accept_stream. Fired when a new stream is
    /// queued or a fatal error is set.
    accept_notify: Arc<Notify>,

    /// Sticky fatal error set by the read or write loop.
    err: Option<MuxError>,

    /// Set when the mux is shutting down; the write loop should flush and exit.
    shutdown: bool,

    /// Next stream ID to assign. Incremented by 2 to preserve dialer/acceptor parity.
    next_id: u32,
}

/// Join handles for the background read and write loop tasks.
struct TaskHandles {
    read_handle: tokio::task::JoinHandle<()>,
    write_handle: tokio::task::JoinHandle<()>,
}

// ---------------------------------------------------------------------------
// Mux
// ---------------------------------------------------------------------------

/// A Mux multiplexes multiple duplex [`Stream`]s onto a single connection.
pub struct Mux {
    state: Arc<StdMutex<MuxState>>,
    write_notify: Arc<Notify>,
    settings: ConnSettings,
    tasks: Option<TaskHandles>,
}

impl Mux {
    /// Wait for and return the next peer-initiated stream.
    pub async fn accept_stream(&self) -> Result<Stream, MuxError> {
        // Clone the Arc once so we can call notified() without holding the lock.
        let accept_notify = self.state.lock().unwrap().accept_notify.clone();
        loop {
            // Prepare the notification listener BEFORE checking state to avoid
            // a race where a stream arrives between the check and the await.
            let notified = accept_notify.notified();
            {
                let mut s = self.state.lock().unwrap();
                if let Some(stream) = s.accept_queue.pop_front() {
                    return Ok(stream);
                }
                if let Some(ref err) = s.err {
                    return Err(err.clone());
                }
            }
            notified.await;
        }
    }

    /// Create a new locally-initiated stream. No I/O is performed; the peer
    /// will not be aware of the new stream until data is written.
    pub fn dial_stream(&self) -> Result<Stream, MuxError> {
        let mut s = self.state.lock().unwrap();

        if let Some(ref err) = s.err {
            return Err(err.clone());
        }
        if s.shutdown {
            return Err(MuxError::ClosedConn);
        }

        let id = s.next_id;
        s.next_id += 2;
        // Wraparound when next_id grows too large
        if s.next_id >= u32::MAX >> 2 {
            let parity = id & 1;
            s.next_id = ID_LOWEST_STREAM + parity;
        }

        let ss = Arc::new(StdMutex::new(StreamState {
            read_buf: BytesMut::new(),
            err: None,
            waker: None,
        }));
        s.streams.insert(id, ss.clone());

        Ok(Stream {
            id,
            stream_state: ss,
            mux_state: self.state.clone(),
            write_notify: self.write_notify.clone(),
            settings: self.settings,
            established: false,
            closed: false,
            read_deadline: None,
            write_deadline: None,
            deadline_sleep: None,
        })
    }

    /// Close the mux, flushing any buffered writes first.
    ///
    /// Returns `Ok(())` if the mux was healthy or had already been closed by
    /// either side. Returns `Err` with the pre-existing error if the mux had
    /// failed for another reason (e.g. stream flood, I/O error).
    pub async fn close(mut self) -> Result<(), MuxError> {
        // Signal shutdown via shared state
        {
            let mut s = self.state.lock().unwrap();
            s.shutdown = true;
        }
        self.write_notify.notify_one();

        // Take handles so we can await write and abort read.
        let (write_handle, read_handle) = match self.tasks.take() {
            Some(h) => (Some(h.write_handle), Some(h.read_handle)),
            None => (None, None),
        };

        // Wait for write loop to flush and exit. If it already exited (e.g.
        // due to an I/O error), this returns immediately — no oneshot race.
        if let Some(wh) = write_handle {
            let _ = wh.await;
        }

        // Snapshot any pre-existing fatal error before we overwrite it.
        let prior_err = self.state.lock().unwrap().err.clone();

        // Set fatal error on all streams
        set_fatal_error(&self.state, MuxError::ClosedConn);

        // Detach the read loop with a grace period rather than aborting it
        // immediately. Aborting would drop the ReadHalf immediately; combined
        // with the already-dropped WriteHalf that zeros the Arc on the
        // underlying connection, the OS sends a TCP RST that clears the peer's
        // receive buffer — losing frames still in transit.
        //
        // Instead, spawn a task that waits READ_LOOP_GRACE_PERIOD for the peer
        // to send EOF (their FIN in response to ours), then forcibly aborts the
        // read loop. This bounds resource lifetime: a cooperative peer closes
        // within milliseconds; a hanging peer is cleaned up within the grace
        // period.
        if let Some(mut rh) = read_handle {
            tokio::spawn(async move {
                if time::timeout(READ_LOOP_GRACE_PERIOD, &mut rh)
                    .await
                    .is_err()
                {
                    rh.abort();
                }
            });
        }

        match prior_err {
            None | Some(MuxError::ClosedConn) | Some(MuxError::PeerClosedConn) => Ok(()),
            Some(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

/// A Stream is a duplex connection multiplexed over a single connection.
pub struct Stream {
    id: u32,
    stream_state: Arc<StdMutex<StreamState>>,
    mux_state: Arc<StdMutex<MuxState>>,
    write_notify: Arc<Notify>,
    settings: ConnSettings,
    established: bool,
    closed: bool,
    read_deadline: Option<time::Instant>,
    write_deadline: Option<time::Instant>,
    /// Pinned timer reused across polls to avoid spawning a new task per
    /// Pending return. Reset to the active deadline; polled alongside the
    /// data/write channel so the waker fires when the deadline expires.
    deadline_sleep: Option<Pin<Box<time::Sleep>>>,
}

impl Stream {
    /// Set both read and write deadlines.
    pub fn set_deadline(&mut self, t: Option<time::Instant>) {
        self.read_deadline = t;
        self.write_deadline = t;
    }

    /// Set the read deadline.
    pub fn set_read_deadline(&mut self, t: Option<time::Instant>) {
        self.read_deadline = t;
    }

    /// Set the write deadline.
    pub fn set_write_deadline(&mut self, t: Option<time::Instant>) {
        self.write_deadline = t;
    }

    /// Gracefully close this stream. Sends FLAG_LAST to the peer.
    pub fn close(&mut self) -> Result<(), MuxError> {
        if self.closed {
            return Ok(());
        }
        let err = self.send_close_frame();
        match err {
            Some(MuxError::PeerClosedConn | MuxError::ClosedConn) | None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// Append a FLAG_LAST frame to the write buffer, move the stream from
    /// active to closing, and notify the write loop. Returns any pre-existing
    /// fatal error from the mux.
    fn send_close_frame(&mut self) -> Option<MuxError> {
        self.closed = true;

        let header = FrameHeader {
            id: self.id,
            length: 0,
            flags: FLAG_LAST,
        };

        let err = {
            let mut s = self.mux_state.lock().unwrap();
            let err = s.err.clone();
            append_frame(&mut s.write_buf, header, &[]);
            s.streams.remove(&self.id);
            s.closing.insert(
                self.id,
                ClosingStreamEntry {
                    frame_count: 0,
                    closed: time::Instant::now(),
                },
            );
            err
        };

        self.write_notify.notify_one();
        err
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.send_close_frame();
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Peer doesn't know this stream exists until we write the first frame.
        if !this.established {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read called before write on newly-dialed stream",
            )));
        }

        // Check deadline
        if let Some(deadline) = this.read_deadline
            && time::Instant::now() >= deadline
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "read deadline exceeded",
            )));
        }

        // Lock per-stream state
        let mut ss = this.stream_state.lock().unwrap();

        // If data is available, return it
        if !ss.read_buf.is_empty() {
            let n = buf.remaining().min(ss.read_buf.len());
            buf.put_slice(&ss.read_buf[..n]);
            let _ = ss.read_buf.split_to(n);
            return Poll::Ready(Ok(()));
        }

        // No data — check error
        if let Some(ref err) = ss.err {
            return match err {
                MuxError::PeerClosedStream => Poll::Ready(Ok(())), // EOF
                e => Poll::Ready(Err(e.clone().into())),
            };
        }

        // Register waker and return Pending
        ss.waker = Some(cx.waker().clone());
        drop(ss);

        if let Some(deadline) = this.read_deadline {
            let sleep = this
                .deadline_sleep
                .get_or_insert_with(|| Box::pin(time::sleep_until(deadline)));
            sleep.as_mut().reset(deadline);
            let _ = sleep.as_mut().poll(cx);
        }

        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                MuxError::ClosedStream,
            )));
        }

        // Check deadline
        if let Some(deadline) = this.write_deadline
            && time::Instant::now() >= deadline
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "write deadline exceeded",
            )));
        }

        let max_payload = this.settings.max_payload_size();
        let n = buf.len().min(max_payload);
        let frame_size = FRAME_HEADER_SIZE + n;

        let mut s = this.mux_state.lock().unwrap();

        // Check fatal error
        if let Some(ref err) = s.err {
            return Poll::Ready(Err(err.clone().into()));
        }

        // Backpressure check
        let max_buf_size = max_payload * MAX_WRITE_BUF_FACTOR;
        if s.write_buf.len() + frame_size > max_buf_size {
            s.buffer_wakers.push_back(cx.waker().clone());
            drop(s);
            if let Some(deadline) = this.write_deadline {
                let sleep = this
                    .deadline_sleep
                    .get_or_insert_with(|| Box::pin(time::sleep_until(deadline)));
                sleep.as_mut().reset(deadline);
                let _ = sleep.as_mut().poll(cx);
            }
            return Poll::Pending;
        }

        // Build header
        let mut flags = 0u16;
        if !this.established {
            flags |= FLAG_FIRST;
            this.established = true;
        }

        let header = FrameHeader {
            id: this.id,
            length: n as u16,
            flags,
        };

        // Single copy: directly into shared write buffer
        append_frame(&mut s.write_buf, header, &buf[..n]);

        // Chain-wake: if there's still buffer space, wake the next
        // backpressured writer so it can append without waiting for
        // the write loop to drain.
        if s.write_buf.len() + frame_size <= max_buf_size
            && let Some(w) = s.buffer_wakers.pop_front()
        {
            w.wake();
        }

        drop(s);

        // Wake write loop
        this.write_notify.notify_one();

        Poll::Ready(Ok(n))
    }

    /// No-op. Writes are buffered in shared memory and flushed to the
    /// wire asynchronously by the mux write loop; there is no mechanism
    /// to block until a specific write has been transmitted.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().close().map_err(Into::into))
    }
}

// ---------------------------------------------------------------------------
// read_loop
// ---------------------------------------------------------------------------

async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: PacketReader<R, SeqCipher>,
    mux_state: Arc<StdMutex<MuxState>>,
    write_notify: Arc<Notify>,
    settings: ConnSettings,
) {
    loop {
        let (h, payload) = match reader.next_frame().await {
            Ok(frame) => frame,
            Err(e) => {
                let err = if packet_reader_error_is_conn_close(&e) {
                    MuxError::PeerClosedConn
                } else {
                    MuxError::Io(e.to_string())
                };
                set_fatal_error(&mux_state, err);
                return;
            }
        };

        if h.id == ID_KEEPALIVE {
            continue;
        }
        if h.id < ID_LOWEST_STREAM {
            set_fatal_error(&mux_state, MuxError::InvalidFrameId(h.id));
            return;
        }

        // Determine action under the mux lock, then execute outside it.
        // We extract the Arc<StdMutex<StreamState>> to deliver data without
        // holding the mux lock.
        enum Action {
            /// Deliver payload to an existing stream.
            Data(Arc<StdMutex<StreamState>>),
            /// Close a stream (FLAG_LAST received).
            Close(Arc<StdMutex<StreamState>>, MuxError),
            /// Fatal error — terminate the read loop.
            Fatal(MuxError),
            /// Frame was handled inline — continue.
            Continue,
        }

        let action = {
            let mut s = mux_state.lock().unwrap();

            if let Some(ss) = s.streams.get(&h.id) {
                if h.flags & FLAG_LAST != 0 {
                    // Peer closing this stream
                    let err = if h.flags & FLAG_ERROR != 0 {
                        MuxError::PeerError(String::from_utf8_lossy(&payload).into_owned())
                    } else {
                        MuxError::PeerClosedStream
                    };
                    let ss = s.streams.remove(&h.id).unwrap();
                    s.closing.remove(&h.id);
                    Action::Close(ss, err)
                } else {
                    Action::Data(ss.clone())
                }
            } else if h.flags & FLAG_FIRST != 0 {
                if s.streams.len() >= MAX_STREAMS {
                    Action::Fatal(MuxError::TooManyStreams)
                } else {
                    let ss = Arc::new(StdMutex::new(StreamState {
                        read_buf: BytesMut::new(),
                        err: None,
                        waker: None,
                    }));
                    s.streams.insert(h.id, ss.clone());

                    let stream = Stream {
                        id: h.id,
                        stream_state: ss.clone(),
                        mux_state: mux_state.clone(),
                        write_notify: write_notify.clone(),
                        settings,
                        established: true,
                        closed: false,
                        read_deadline: None,
                        write_deadline: None,
                        deadline_sleep: None,
                    };

                    s.accept_queue.push_back(stream);
                    // Clone notify before dropping the lock so we can fire it
                    // without holding the mux lock.
                    let accept_notify = s.accept_notify.clone();
                    drop(s);
                    accept_notify.notify_one();

                    // Deliver initial payload (if any) via the Data path
                    if payload.is_empty() {
                        continue;
                    }
                    Action::Data(ss)
                }
            } else {
                // Unknown stream
                if let Some(cs) = s.closing.get_mut(&h.id) {
                    cs.frame_count += 1;
                    if cs.frame_count >= MAX_CLOSED_FRAMES {
                        Action::Fatal(MuxError::StreamFlood)
                    } else {
                        Action::Continue
                    }
                } else {
                    Action::Fatal(MuxError::UnknownStream)
                }
            }
        }; // MuxState lock dropped here (for non-FLAG_FIRST paths)

        match action {
            Action::Data(ss) => {
                let mut state = ss.lock().unwrap();
                if state.err.is_none() {
                    state.read_buf.extend_from_slice(&payload);
                    if let Some(w) = state.waker.take() {
                        w.wake();
                    }
                }
            }
            Action::Close(ss, err) => {
                let mut state = ss.lock().unwrap();
                state.err = Some(err);
                if let Some(w) = state.waker.take() {
                    w.wake();
                }
            }
            Action::Fatal(err) => {
                set_fatal_error(&mux_state, err);
                return;
            }
            Action::Continue => {}
        }
    }
}

// ---------------------------------------------------------------------------
// write_loop
// ---------------------------------------------------------------------------

async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: PacketWriter<W, SeqCipher>,
    mux_state: Arc<StdMutex<MuxState>>,
    write_notify: Arc<Notify>,
    settings: ConnSettings,
) {
    let keepalive_interval = settings.max_timeout - settings.max_timeout / 4;
    let mut keepalive_timer = time::interval(keepalive_interval);
    // Skip the immediate first tick
    keepalive_timer.reset();

    let mut last_cleanup = time::Instant::now();

    let max_frame_size = settings.max_frame_size();
    // Local buffer swapped with the shared write_buf each iteration.
    let mut local_buf: Vec<u8> = Vec::with_capacity(max_frame_size * 10);

    loop {
        // Prepare a Notified future BEFORE checking state to avoid a race
        // where a notification arrives between the check and the await.
        let notified = write_notify.notified();

        let has_work = {
            let s = mux_state.lock().unwrap();
            !s.write_buf.is_empty() || s.shutdown
        };

        if !has_work {
            tokio::select! {
                _ = notified => {}
                _ = keepalive_timer.tick() => {}
            }
        }

        // Take the write buffer, wake backpressure waiters
        let is_shutdown = {
            let mut s = mux_state.lock().unwrap();
            if s.err.is_some() {
                return;
            }

            // Swap buffers: take write_buf, give back the cleared local_buf.
            // This is O(1) and reuses allocations across iterations.
            local_buf.clear();
            std::mem::swap(&mut local_buf, &mut s.write_buf);

            if local_buf.is_empty() && !s.shutdown {
                // Must be a keepalive tick
                append_frame(
                    &mut local_buf,
                    FrameHeader {
                        id: ID_KEEPALIVE,
                        length: 0,
                        flags: 0,
                    },
                    &[],
                );
            }

            // Clean up expired closing entries unconditionally so they
            // don't accumulate during sustained write activity.
            let now = time::Instant::now();
            if now.duration_since(last_cleanup) >= CLOSING_STREAM_CLEANUP_INTERVAL {
                s.closing.retain(|_, cs| {
                    now.duration_since(cs.closed) < CLOSING_STREAM_CLEANUP_INTERVAL
                });
                last_cleanup = now;
            }

            // Wake one backpressure-blocked writer. That writer will
            // chain-wake the next after it successfully appends its frame.
            if let Some(w) = s.buffer_wakers.pop_front() {
                w.wake();
            }

            s.shutdown
        };

        // Pad to packet boundary
        if !local_buf.is_empty() {
            let remainder = local_buf.len() % max_frame_size;
            if remainder != 0 {
                let padding = max_frame_size - remainder;
                local_buf.resize(local_buf.len() + padding, 0);
            }
        }

        // Encrypt + I/O (no lock held)
        if !local_buf.is_empty()
            && let Err(e) = writer.write_encrypted(&local_buf).await
        {
            let err = if is_conn_close_error(&e) {
                MuxError::PeerClosedConn
            } else {
                MuxError::Io(e.to_string())
            };
            set_fatal_error(&mux_state, err);
            return;
        }

        // Reset keepalive timer after any successful write
        keepalive_timer.reset();

        if is_shutdown {
            // Shut down the write half so the peer's read_loop receives EOF
            // (TCP FIN). Without this, the WriteHalf drops without sending FIN
            // because the ReadHalf still holds the shared Arc on the socket.
            let _ = writer.shutdown().await;
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn set_fatal_error(mux_state: &Arc<StdMutex<MuxState>>, err: MuxError) {
    let mut s = mux_state.lock().unwrap();
    if s.err.is_none() {
        s.err = Some(err.clone());
    }
    // Wake all stream readers with the error.
    // Lock ordering: mux lock first, then stream lock (never reverse).
    for (_, ss) in s.streams.drain() {
        let mut state = ss.lock().unwrap();
        state.err = Some(err.clone());
        if let Some(w) = state.waker.take() {
            w.wake();
        }
    }
    // Wake blocked writers
    for w in s.buffer_wakers.drain(..) {
        w.wake();
    }
    // Wake any task blocked in accept_stream
    s.accept_notify.notify_one();
}

pub(crate) fn new_mux<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
    result: HandshakeResult,
    settings: ConnSettings,
    id_offset: u32,
) -> Mux {
    let (read_half, write_half) = tokio::io::split(conn);

    // Construct independent read/write ciphers from the raw key.
    // The writer only uses our_nonce (encrypt), the reader only uses their_nonce (decrypt).
    // HandshakeResult is ZeroizeOnDrop so key material is cleared when `result` drops.
    let mut read_cipher = SeqCipher::new(&result.key);
    read_cipher.our_nonce = result.our_nonce;
    read_cipher.their_nonce = result.their_nonce;
    let mut write_cipher = SeqCipher::new(&result.key);
    write_cipher.our_nonce = result.our_nonce;
    write_cipher.their_nonce = result.their_nonce;

    let packet_reader = PacketReader::new(read_half, read_cipher, settings.packet_size as usize);
    let packet_writer = PacketWriter::new(write_half, write_cipher, settings.packet_size as usize);

    let max_frame_size = settings.max_frame_size();
    let mux_state = Arc::new(StdMutex::new(MuxState {
        write_buf: Vec::with_capacity(max_frame_size * 10),
        buffer_wakers: VecDeque::new(),
        streams: HashMap::new(),
        closing: HashMap::new(),
        accept_queue: VecDeque::new(),
        accept_notify: Arc::new(Notify::new()),
        err: None,
        shutdown: false,
        next_id: ID_LOWEST_STREAM + id_offset,
    }));

    let write_notify = Arc::new(Notify::new());

    let read_state = mux_state.clone();
    let read_write_notify = write_notify.clone();
    let read_handle = tokio::spawn(async move {
        read_loop(packet_reader, read_state, read_write_notify, settings).await;
    });

    let write_state = mux_state.clone();
    let wn = write_notify.clone();
    let write_handle = tokio::spawn(async move {
        write_loop(packet_writer, write_state, wn, settings).await;
    });

    Mux {
        state: mux_state,
        write_notify,
        settings,
        tasks: Some(TaskHandles {
            read_handle,
            write_handle,
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::MuxError;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, sink};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    /// Creates a pair of connected Mux instances using anonymous handshake
    /// over a local TCP connection.
    async fn new_testing_pair() -> (super::Mux, super::Mux) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_fut = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            crate::accept_anonymous(conn).await.unwrap()
        });

        let dial_conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let dial_mux = crate::dial_anonymous(dial_conn).await.unwrap();
        let accept_mux = accept_fut.await.unwrap();

        (dial_mux, accept_mux)
    }

    #[tokio::test]
    async fn basic_echo() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        // Server: accept streams and echo back
        let accept_handle = tokio::spawn(async move {
            let mut stream = accept_mux.accept_stream().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.close().unwrap();
            accept_mux.close().await.unwrap();
        });

        // Client: write, read echo, close
        let mut stream = dial_mux.dial_stream().unwrap();
        let msg = b"hello, mux!";
        stream.write_all(msg).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        stream.close().unwrap();
        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }

    #[tokio::test]
    async fn many_streams() {
        let (dial_mux, accept_mux) = new_testing_pair().await;
        let num_streams = 100;

        // Server: accept streams and echo back
        let accept_handle = tokio::spawn(async move {
            for _ in 0..num_streams {
                let mut stream = accept_mux.accept_stream().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap();
                    stream.write_all(&buf[..n]).await.unwrap();
                    stream.close().unwrap();
                });
            }
            // Wait a bit for all streams to finish, then close
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            accept_mux.close().await.unwrap();
        });

        // Client: open many streams concurrently
        let mut handles = Vec::new();
        for i in 0..num_streams {
            let mut stream = dial_mux.dial_stream().unwrap();
            handles.push(tokio::spawn(async move {
                let msg = format!("stream {i}");
                stream.write_all(msg.as_bytes()).await.unwrap();
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
                stream.close().unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }

    #[tokio::test]
    async fn deadline_read() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        // Server: accept stream but never write anything
        let accept_handle = tokio::spawn(async move {
            let _stream = accept_mux.accept_stream().await.unwrap();
            // Hold the stream open but don't write
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            accept_mux.close().await.unwrap();
        });

        let mut stream = dial_mux.dial_stream().unwrap();
        // Write something so the stream is established
        stream.write_all(b"hello").await.unwrap();

        // Set a short read deadline
        stream.set_read_deadline(Some(
            tokio::time::Instant::now() + std::time::Duration::from_millis(50),
        ));

        // Read should timeout
        let mut buf = vec![0u8; 1024];
        let result = stream.read(&mut buf).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // Clear deadline — set to None
        stream.set_read_deadline(None);

        stream.close().unwrap();
        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }

    /// Verify that `AsyncWrite::shutdown()` sends FLAG_LAST so the peer
    /// observes a clean EOF instead of hanging forever.
    #[tokio::test]
    async fn shutdown_sends_flag_last() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        let accept_handle = tokio::spawn(async move {
            let mut stream = accept_mux.accept_stream().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            // Wait for peer to close — should see EOF, not hang.
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, 0, "expected EOF after peer shutdown");
            stream.close().unwrap();
            accept_mux.close().await.unwrap();
        });

        let mut stream = dial_mux.dial_stream().unwrap();
        let msg = b"shutdown test";
        stream.write_all(msg).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        // Use AsyncWrite::shutdown instead of Stream::close
        stream.shutdown().await.unwrap();
        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }

    /// Verify that dropping a stream without calling close() still sends
    /// FLAG_LAST to the peer via the shared write buffer in Drop.
    #[tokio::test]
    async fn drop_sends_flag_last() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        let accept_handle = tokio::spawn(async move {
            let mut stream = accept_mux.accept_stream().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"drop test");
            // Peer drops without close — should still see EOF.
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, 0, "expected EOF after peer drop");
            stream.close().unwrap();
            accept_mux.close().await.unwrap();
        });

        {
            let mut stream = dial_mux.dial_stream().unwrap();
            stream.write_all(b"drop test").await.unwrap();
            // stream is dropped here without close()
        }

        // Give the write loop a moment to flush the FLAG_LAST frame.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }

    #[tokio::test]
    async fn sustained_write() {
        // Use DuplexStream to eliminate TCP as a variable
        let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);

        let accept_handle =
            tokio::spawn(async move { crate::accept_anonymous(server_conn).await.unwrap() });
        let dial_mux = crate::dial_anonymous(client_conn).await.unwrap();
        let accept_mux = accept_handle.await.unwrap();

        // Server: accept one stream, discard all data
        let server = tokio::spawn(async move {
            let mut stream = accept_mux.accept_stream().await.unwrap();
            let _ = copy(&mut stream, &mut sink()).await;
            drop(stream);
            accept_mux
        });

        let settings = crate::handshake::ConnSettings::default();
        let buf = vec![0u8; settings.max_payload_size()];
        let mut stream = dial_mux.dial_stream().unwrap();

        for i in 0..10_000 {
            if let Err(e) = stream.write_all(&buf).await {
                panic!("write_all failed on iteration {i}: {e}");
            }
        }

        stream.close().unwrap();
        let accept_mux = server.await.unwrap();
        accept_mux.close().await.unwrap();
        dial_mux.close().await.unwrap();
    }

    /// Verifies that writes larger than max_payload_size are correctly split
    /// into multiple frames and reassembled without data loss.
    #[tokio::test]
    async fn large_write_frame_splitting() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        let settings = crate::handshake::ConnSettings::default();
        let max_payload = settings.max_payload_size();

        // Test several sizes: exactly max, max+1, 3x max, and a non-aligned size.
        let test_sizes: Vec<usize> = vec![
            max_payload,
            max_payload + 1,
            max_payload * 3,
            max_payload * 3 + 7,
        ];
        let test_sizes_clone = test_sizes.clone();

        let accept_handle = tokio::spawn(async move {
            for expected_size in test_sizes_clone {
                let mut stream = accept_mux.accept_stream().await.unwrap();
                let mut received = Vec::new();
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..n]);
                }
                assert_eq!(
                    received.len(),
                    expected_size,
                    "server: size mismatch for write of {expected_size} bytes"
                );
                let expected: Vec<u8> = (0..expected_size).map(|i| (i % 251) as u8).collect();
                assert_eq!(
                    received, expected,
                    "server: content corrupted for write of {expected_size} bytes"
                );
                stream.close().unwrap();
            }
            accept_mux.close().await.unwrap();
        });

        for size in &test_sizes {
            let mut stream = dial_mux.dial_stream().unwrap();
            let data: Vec<u8> = (0..*size).map(|i| (i % 251) as u8).collect();
            stream.write_all(&data).await.unwrap();
            stream.close().unwrap();
        }

        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }

    /// Verifies that calling `close()` while the peer still has frames buffered
    /// does not send a TCP RST that would discard those frames.
    ///
    /// Before the fix, `close()` aborted the read_loop task, which dropped the
    /// ReadHalf. With both halves gone the TcpStream was dropped and the OS
    /// sent a RST, clearing the peer's receive buffer. The fix detaches the
    /// read_loop (`drop(handle)`) so the ReadHalf stays alive until the task
    /// exits naturally via EOF, allowing the peer to finish reading.
    #[tokio::test]
    async fn close_preserves_in_flight_frames() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        let settings = crate::handshake::ConnSettings::default();
        let frame_size = settings.max_payload_size();
        let num_frames = 10usize;

        // Accept side: receive all frames, verify content.
        let accept_handle = tokio::spawn(async move {
            let mut stream = accept_mux.accept_stream().await.unwrap();
            let mut received = Vec::new();
            let mut buf = vec![0u8; 8192];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            let expected_len = num_frames * frame_size;
            assert_eq!(
                received.len(),
                expected_len,
                "lost {} bytes — likely caused by TCP RST from premature ReadHalf drop",
                expected_len - received.len()
            );
            let expected: Vec<u8> = (0..expected_len).map(|i| (i % 251) as u8).collect();
            assert_eq!(received, expected, "data corrupted");
            stream.close().unwrap();
            accept_mux.close().await.unwrap();
        });

        // Dial side: write all frames, then immediately close() before the
        // accept side has had a chance to read everything.
        let mut stream = dial_mux.dial_stream().unwrap();
        let total = num_frames * frame_size;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        stream.write_all(&data).await.unwrap();
        stream.close().unwrap();

        // Close the dial mux immediately — this is the critical moment.
        // With `rh.abort()` this races against the accept side reading; with
        // `drop(read_handle)` the ReadHalf stays alive until the task finishes.
        dial_mux.close().await.unwrap();

        accept_handle.await.unwrap();
    }

    /// Verifies that the read loop is forcibly aborted within READ_LOOP_GRACE_PERIOD
    /// when the peer never closes its write side after we call close().
    ///
    /// Without the grace-period abort, a peer that hangs indefinitely keeps the
    /// read_loop task and its ReadHalf alive forever, leaking the connection.
    ///
    /// Uses an in-memory duplex stream (not TCP) so that all I/O is driven
    /// purely by the tokio scheduler — no OS-level I/O events that might not
    /// fire reliably in paused-clock mode.
    #[tokio::test(start_paused = true)]
    async fn close_read_loop_aborted_after_grace_period() {
        let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);

        let accept_fut =
            tokio::spawn(async move { crate::accept_anonymous(server_conn).await.unwrap() });
        let dial_mux = crate::dial_anonymous(client_conn).await.unwrap();
        let accept_mux = accept_fut.await.unwrap();

        // Weak pointer into dial_mux's state — the only remaining holder after
        // close() consumes the Mux is the read_loop task itself. Once the task
        // is aborted the Arc refcount hits zero and upgrade() returns None.
        let state_weak = std::sync::Arc::downgrade(&dial_mux.state);

        // close() must complete without needing time to advance (no timers
        // block the shutdown path — only write_notify is needed).
        dial_mux.close().await.unwrap();

        // The peer (accept_mux) is still alive and has not called close(), so
        // its write side is still open. The dial_mux's read_loop is blocked
        // waiting for frames that will never arrive.
        assert!(
            state_weak.upgrade().is_some(),
            "state freed too early — read_loop should still be running"
        );

        // Yield once so the cleanup task gets its first poll and registers its
        // Sleep at t=0+GRACE_PERIOD. Without this yield, the Sleep is created
        // after the advance and misses the window.
        tokio::task::yield_now().await;

        // Advance time past the grace period to fire the cleanup task's timer.
        tokio::time::advance(super::READ_LOOP_GRACE_PERIOD + std::time::Duration::from_millis(100))
            .await;
        // Yield repeatedly:
        //   - first passes let the cleanup task wake, call rh.abort(), and exit
        //   - subsequent passes let the read_loop task receive the abort
        //     signal, drop its future, and release the Arc<MuxState>
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }

        assert!(
            state_weak.upgrade().is_none(),
            "read_loop task was not cleaned up after grace period"
        );

        let _ = accept_mux.close().await;
    }

    /// Verifies that the mux tolerates straggler frames for a closed stream
    /// (below MAX_CLOSED_FRAMES) but kills the connection when the threshold
    /// is exceeded (stream flood).
    #[tokio::test]
    async fn stream_flood_detection() {
        // MAX_CLOSED_FRAMES is 1000. Each write() call produces one frame, and
        // dropping the stream without close() adds one FLAG_LAST frame via Drop.

        // --- Below threshold: mux survives ---
        {
            let (dial_mux, accept_mux) = new_testing_pair().await;

            let accept_handle = tokio::spawn(async move {
                let mut stream = accept_mux.accept_stream().await.unwrap();
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf).await;
                // Wait for the dialer's FLAG_LAST to arrive
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                // Write 999 frames. Drop will add 1 more (FLAG_LAST) = 1000 total.
                // frame_count >= 1000 triggers flood, so 999 frames should be the
                // last safe value. The Drop adds frame 1000, which triggers flood.
                // To stay below, we need 998 writes + 1 Drop = 999 < 1000.
                let payload = [0u8; 64];
                for _ in 0..998 {
                    let _ = stream.write(&payload).await;
                }
                // stream is dropped here → sends FLAG_LAST (frame 999)
                // 999 total frames < 1000 threshold
                drop(stream);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                accept_mux
            });

            let mut stream = dial_mux.dial_stream().unwrap();
            stream.write_all(b"hello").await.unwrap();
            stream.close().unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            // Mux should still be alive
            let mut stream2 = dial_mux
                .dial_stream()
                .expect("mux should survive 999 straggler frames");
            stream2.write_all(b"still alive").await.unwrap();
            stream2.close().unwrap();

            let accept_mux = accept_handle.await.unwrap();
            accept_mux.close().await.unwrap();
            dial_mux.close().await.unwrap();
        }

        // --- At threshold: mux dies with StreamFlood ---
        {
            let (dial_mux, accept_mux) = new_testing_pair().await;

            let accept_handle = tokio::spawn(async move {
                let mut stream = accept_mux.accept_stream().await.unwrap();
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                // 999 writes + 1 Drop FLAG_LAST = 1000 total → triggers flood
                let payload = [0u8; 64];
                for _ in 0..999 {
                    if stream.write(&payload).await.is_err() {
                        break;
                    }
                }
                // stream dropped → FLAG_LAST = frame 1000 → triggers flood
                drop(stream);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                accept_mux
            });

            let mut stream = dial_mux.dial_stream().unwrap();
            stream.write_all(b"hello").await.unwrap();
            stream.close().unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            // Mux should be dead
            let result = dial_mux.dial_stream();
            assert!(result.is_err(), "expected mux to be dead from stream flood");

            let accept_mux = accept_handle.await.unwrap();
            let _ = accept_mux.close().await;
            let _ = dial_mux.close().await;
        }
    }

    #[tokio::test]
    async fn accept_notify() {
        let (dial_mux, accept_mux) = new_testing_pair().await;

        let accept_handle = tokio::spawn(async move { accept_mux.accept_stream().await });

        dial_mux.close().await.unwrap();

        match timeout(Duration::from_millis(500), accept_handle)
            .await
            .expect("accept_stream hung after peer closed")
            .expect("join error")
        {
            Ok(_) => panic!("expected accept_stream to fail after peer closed"),
            Err(e) => assert!(
                matches!(e, MuxError::PeerClosedConn),
                "expected accept_stream to return PeerClosedConn after peer closed, got {e:?}"
            ),
        }
    }
}
