use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot};
use tokio::time;
use tokio_util::sync::PollSender;

use crate::frame::{
    FLAG_ERROR, FLAG_FIRST, FLAG_LAST, FrameHeader, ID_KEEPALIVE, ID_LOWEST_STREAM, PacketReader,
    PacketWriter, append_frame,
};
use crate::handshake::{ConnSettings, SeqCipher};

/// Grace period before removing a closed stream from tracking.
const CLOSING_STREAM_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum frames to accept for a closed stream before treating it as a flood.
const MAX_CLOSED_FRAMES: u16 = 1000;

/// Maximum concurrent streams.
const MAX_STREAMS: usize = 1 << 20;

/// Backpressure limit for write commands queued to the write loop.
const WRITE_CHANNEL_CAPACITY: usize = 10;

/// Backpressure limit for incoming streams waiting to be accepted.
const ACCEPT_CHANNEL_CAPACITY: usize = 256;

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

/// A single frame queued for transmission by the write loop.
struct WriteFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

/// Commands sent to the write loop via the shared channel.
enum WriteCmd {
    /// Enqueue a frame for encryption and transmission.
    Frame(WriteFrame),
    /// Gracefully shut down the write loop, signalling completion via the sender.
    Shutdown(oneshot::Sender<()>),
}

/// Per-stream handle held by the read loop to deliver data and signal closure.
struct StreamHandle {
    /// Channel for delivering frame payloads to the stream's reader.
    data_tx: mpsc::Sender<Vec<u8>>,
    /// Shared slot set when the stream is closed, communicating the reason to the reader.
    close_err: Arc<StdMutex<Option<MuxError>>>,
}

/// Tracks a recently-closed stream to absorb in-flight frames from the peer.
struct ClosingStreamEntry {
    /// Number of frames received since closure (flood detection).
    frame_count: u16,
    /// When the stream was closed, used for periodic cleanup.
    closed: time::Instant,
}

/// Central registry of all active and recently-closed streams for a mux.
struct StreamRegistry {
    /// Active streams indexed by stream ID.
    streams: HashMap<u32, StreamHandle>,
    /// Recently-closed streams kept around to absorb straggler frames.
    closing: HashMap<u32, ClosingStreamEntry>,
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
    write_tx: mpsc::Sender<WriteCmd>,
    accept_rx: TokioMutex<mpsc::Receiver<Stream>>,
    next_id: AtomicU32,
    registry: Arc<StdMutex<StreamRegistry>>,
    settings: ConnSettings,
    tasks: TokioMutex<Option<TaskHandles>>,
}

impl Mux {
    /// Wait for and return the next peer-initiated stream.
    pub async fn accept_stream(&self) -> Result<Stream, MuxError> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv().await.ok_or(MuxError::ClosedConn)
    }

    /// Create a new locally-initiated stream. No I/O is performed; the peer
    /// will not be aware of the new stream until data is written.
    pub fn dial_stream(&self) -> Result<Stream, MuxError> {
        let mut reg = self.registry.lock().unwrap();

        if self.write_tx.is_closed() {
            return Err(MuxError::ClosedConn);
        }

        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        // Wraparound when next_id grows too large
        if id >= u32::MAX >> 2 {
            let parity = id & 1;
            self.next_id
                .store(ID_LOWEST_STREAM + parity, Ordering::Relaxed);
        }

        let (data_tx, data_rx) = mpsc::channel(1);
        let close_err = Arc::new(StdMutex::new(None));
        reg.streams.insert(
            id,
            StreamHandle {
                data_tx,
                close_err: close_err.clone(),
            },
        );

        let write_tx = self.write_tx.clone();
        Ok(Stream {
            id,
            data_rx,
            close_err,
            poll_sender: PollSender::new(write_tx.clone()),
            write_tx,
            registry: self.registry.clone(),
            settings: self.settings,
            read_buf: Vec::new(),
            established: false,
            closed: false,
            read_deadline: None,
            write_deadline: None,
        })
    }

    /// Close the mux, flushing any buffered writes first.
    pub async fn close(self) -> Result<(), MuxError> {
        // Send shutdown command to write loop and wait for it to flush
        let (tx, rx) = oneshot::channel();
        let _ = self.write_tx.send(WriteCmd::Shutdown(tx)).await;
        let _ = rx.await;

        // Set fatal error on all streams
        set_fatal_error(&self.registry, MuxError::ClosedConn);

        // Abort background tasks
        if let Some(handles) = self.tasks.lock().await.take() {
            handles.read_handle.abort();
            handles.write_handle.abort();
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

/// A Stream is a duplex connection multiplexed over a single connection.
pub struct Stream {
    id: u32,
    data_rx: mpsc::Receiver<Vec<u8>>,
    close_err: Arc<StdMutex<Option<MuxError>>>,
    write_tx: mpsc::Sender<WriteCmd>,
    poll_sender: PollSender<WriteCmd>,
    registry: Arc<StdMutex<StreamRegistry>>,
    settings: ConnSettings,
    read_buf: Vec<u8>,
    established: bool,
    closed: bool,
    read_deadline: Option<time::Instant>,
    write_deadline: Option<time::Instant>,
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
    pub async fn close(&mut self) -> Result<(), MuxError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        // Send FLAG_LAST frame
        let h = FrameHeader {
            id: self.id,
            length: 0,
            flags: FLAG_LAST,
        };
        let result = self
            .write_tx
            .send(WriteCmd::Frame(WriteFrame {
                header: h,
                payload: Vec::new(),
            }))
            .await;

        // Move from streams to closing in the registry
        {
            let mut reg = self.registry.lock().unwrap();
            reg.streams.remove(&self.id);
            reg.closing.insert(
                self.id,
                ClosingStreamEntry {
                    frame_count: 0,
                    closed: time::Instant::now(),
                },
            );
        }

        match result {
            Ok(()) => Ok(()),
            Err(_) => {
                // Write loop is gone; check if it's a known close
                let err = self.close_err.lock().unwrap().clone();
                match err {
                    Some(MuxError::PeerClosedConn) | Some(MuxError::ClosedConn) | None => Ok(()),
                    Some(e) => Err(e),
                }
            }
        }
    }

    /// Check for a sticky close error.
    fn check_close_err(&self) -> Option<MuxError> {
        self.close_err.lock().unwrap().clone()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain leftover read_buf first
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
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

        // Poll for next data from read loop
        match this.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.read_buf = data[n..].to_vec();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — check why
                match this.check_close_err() {
                    Some(MuxError::PeerClosedStream) | None => {
                        // EOF
                        Poll::Ready(Ok(()))
                    }
                    Some(e) => Poll::Ready(Err(e.into())),
                }
            }
            Poll::Pending => {
                // If we have a deadline, register a timer to wake us
                if let Some(deadline) = this.read_deadline {
                    let waker = cx.waker().clone();
                    tokio::spawn(async move {
                        time::sleep_until(deadline).await;
                        waker.wake();
                    });
                }
                Poll::Pending
            }
        }
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

        // Reserve capacity on the write channel
        match this.poll_sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                let err = this.check_close_err().unwrap_or(MuxError::ClosedConn);
                return Poll::Ready(Err(err.into()));
            }
            Poll::Pending => {
                if let Some(deadline) = this.write_deadline {
                    let waker = cx.waker().clone();
                    tokio::spawn(async move {
                        time::sleep_until(deadline).await;
                        waker.wake();
                    });
                }
                return Poll::Pending;
            }
        }

        let max_payload = this.settings.max_payload_size();
        let n = buf.len().min(max_payload);

        let mut flags = 0u16;
        if !this.established {
            flags |= FLAG_FIRST;
            this.established = true;
        }

        let frame = WriteCmd::Frame(WriteFrame {
            header: FrameHeader {
                id: this.id,
                length: n as u16,
                flags,
            },
            payload: buf[..n].to_vec(),
        });

        match this.poll_sender.send_item(frame) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_) => {
                let err = this.check_close_err().unwrap_or(MuxError::ClosedConn);
                Poll::Ready(Err(err.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.closed = true;
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// read_loop
// ---------------------------------------------------------------------------

/// Actions determined by the read loop under the lock, executed outside the lock.
enum ReadAction {
    /// Send data to an existing stream.
    SendData {
        tx: mpsc::Sender<Vec<u8>>,
        payload: Vec<u8>,
    },
    /// A new stream was created; send it to the accept channel, then optionally
    /// deliver initial payload data.
    NewStream {
        stream: Stream,
        data_tx: Option<mpsc::Sender<Vec<u8>>>,
        payload: Vec<u8>,
    },
    /// Fatal error — terminate the read loop.
    Fatal(MuxError),
    /// Frame was handled inline (stream closure, absorbing straggler frames) — continue.
    Continue,
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: PacketReader<R, SeqCipher>,
    accept_tx: mpsc::Sender<Stream>,
    write_tx: mpsc::Sender<WriteCmd>,
    registry: Arc<StdMutex<StreamRegistry>>,
    settings: ConnSettings,
) {
    let mut frame_buf = vec![0u8; settings.max_payload_size()];

    loop {
        let (h, payload) = match reader.next_frame(&mut frame_buf).await {
            Ok((h, p)) => (h, p.to_vec()),
            Err(e) => {
                let err =
                    if is_conn_close_error(&io::Error::other(e.to_string())) {
                        MuxError::PeerClosedConn
                    } else {
                        MuxError::Io(e.to_string())
                    };
                set_fatal_error(&registry, err);
                return;
            }
        };

        if h.id == ID_KEEPALIVE {
            continue;
        }
        if h.id < ID_LOWEST_STREAM {
            set_fatal_error(&registry, MuxError::InvalidFrameId(h.id));
            return;
        }

        // Determine action under the lock
        let action = {
            let mut reg = registry.lock().unwrap();

            if let Some(handle) = reg.streams.get(&h.id) {
                if h.flags & FLAG_LAST != 0 {
                    // Peer closing this stream
                    let err = if h.flags & FLAG_ERROR != 0 {
                        MuxError::PeerError(String::from_utf8_lossy(&payload).into_owned())
                    } else {
                        MuxError::PeerClosedStream
                    };
                    *handle.close_err.lock().unwrap() = Some(err);
                    reg.streams.remove(&h.id);
                    reg.closing.remove(&h.id);
                    ReadAction::Continue
                } else {
                    ReadAction::SendData {
                        tx: handle.data_tx.clone(),
                        payload,
                    }
                }
            } else if h.flags & FLAG_FIRST != 0 {
                if reg.streams.len() >= MAX_STREAMS {
                    ReadAction::Fatal(MuxError::TooManyStreams)
                } else {
                    let (data_tx, data_rx) = mpsc::channel(1);
                    let close_err = Arc::new(StdMutex::new(None));
                    reg.streams.insert(
                        h.id,
                        StreamHandle {
                            data_tx: data_tx.clone(),
                            close_err: close_err.clone(),
                        },
                    );

                    let stream_write_tx = write_tx.clone();
                    let stream = Stream {
                        id: h.id,
                        data_rx,
                        close_err,
                        poll_sender: PollSender::new(stream_write_tx.clone()),
                        write_tx: stream_write_tx,
                        registry: registry.clone(),
                        settings,
                        read_buf: Vec::new(),
                        established: true,
                        closed: false,
                        read_deadline: None,
                        write_deadline: None,
                    };

                    let initial_tx = if !payload.is_empty() {
                        Some(data_tx)
                    } else {
                        None
                    };

                    ReadAction::NewStream {
                        stream,
                        data_tx: initial_tx,
                        payload,
                    }
                }
            } else {
                // Unknown stream
                if let Some(cs) = reg.closing.get_mut(&h.id) {
                    cs.frame_count += 1;
                    if cs.frame_count >= MAX_CLOSED_FRAMES {
                        ReadAction::Fatal(MuxError::StreamFlood)
                    } else {
                        ReadAction::Continue
                    }
                } else {
                    ReadAction::Fatal(MuxError::UnknownStream)
                }
            }
        }; // MutexGuard dropped here

        // Execute action outside the lock
        match action {
            ReadAction::SendData { tx, payload } => {
                if tx.send(payload).await.is_err() {
                    // Stream was dropped locally — treat as closed
                    continue;
                }
            }
            ReadAction::NewStream {
                stream,
                data_tx,
                payload,
            } => {
                if accept_tx.send(stream).await.is_err() {
                    return; // mux shutting down
                }
                if let Some(tx) = data_tx
                    && tx.send(payload).await.is_err()
                {
                    continue; // stream was closed
                }
            }
            ReadAction::Fatal(err) => {
                set_fatal_error(&registry, err);
                return;
            }
            ReadAction::Continue => {}
        }
    }
}

// ---------------------------------------------------------------------------
// write_loop
// ---------------------------------------------------------------------------

async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: PacketWriter<W, SeqCipher>,
    mut cmd_rx: mpsc::Receiver<WriteCmd>,
    registry: Arc<StdMutex<StreamRegistry>>,
    settings: ConnSettings,
) {
    let keepalive_interval = settings.max_timeout - settings.max_timeout / 4;
    let mut keepalive_timer = time::interval(keepalive_interval);
    // Skip the immediate first tick
    keepalive_timer.reset();

    let mut cleanup_timer = time::interval(CLOSING_STREAM_CLEANUP_INTERVAL);
    cleanup_timer.reset();

    let max_frame_size = settings.max_frame_size();
    let mut write_buf: Vec<u8> = Vec::with_capacity(max_frame_size * 10);

    loop {
        write_buf.clear();

        // Wait for at least one frame, a keepalive tick, or a cleanup tick
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(WriteCmd::Frame(f)) => {
                        append_frame(&mut write_buf, f.header, &f.payload);
                    }
                    Some(WriteCmd::Shutdown(reply)) => {
                        let _ = reply.send(());
                        return;
                    }
                    None => return,
                }
            }
            _ = keepalive_timer.tick() => {
                append_frame(
                    &mut write_buf,
                    FrameHeader { id: ID_KEEPALIVE, length: 0, flags: 0 },
                    &[],
                );
            }
            _ = cleanup_timer.tick() => {
                let mut reg = registry.lock().unwrap();
                let now = time::Instant::now();
                reg.closing.retain(|_, cs| now.duration_since(cs.closed) < CLOSING_STREAM_CLEANUP_INTERVAL);
                continue;
            }
        }

        // Drain additional pending frames (non-blocking)
        loop {
            match cmd_rx.try_recv() {
                Ok(WriteCmd::Frame(f)) => {
                    append_frame(&mut write_buf, f.header, &f.payload);
                    if write_buf.len() >= max_frame_size * 8 {
                        break;
                    }
                }
                Ok(WriteCmd::Shutdown(reply)) => {
                    pad_and_write(&mut write_buf, max_frame_size, &mut writer)
                        .await
                        .ok();
                    let _ = reply.send(());
                    return;
                }
                Err(_) => break,
            }
        }

        // Pad to packet boundary, encrypt, and write
        if let Err(e) = pad_and_write(&mut write_buf, max_frame_size, &mut writer).await {
            let err = if is_conn_close_error(&e) {
                MuxError::PeerClosedConn
            } else {
                MuxError::Io(e.to_string())
            };
            set_fatal_error(&registry, err);
            return;
        }

        // Reset keepalive timer after any successful write
        keepalive_timer.reset();
    }
}

async fn pad_and_write<W: AsyncWrite + Unpin>(
    buf: &mut Vec<u8>,
    max_frame_size: usize,
    writer: &mut PacketWriter<W, SeqCipher>,
) -> Result<(), io::Error> {
    if buf.is_empty() {
        return Ok(());
    }
    // Pad to packet boundary (max_frame_size = packet_size - AEAD_TAG_SIZE)
    let remainder = buf.len() % max_frame_size;
    if remainder != 0 {
        let padding = max_frame_size - remainder;
        buf.resize(buf.len() + padding, 0);
    }
    writer.write_encrypted(buf).await
}

fn set_fatal_error(registry: &Arc<StdMutex<StreamRegistry>>, err: MuxError) {
    let mut reg = registry.lock().unwrap();
    for (_, handle) in reg.streams.drain() {
        *handle.close_err.lock().unwrap() = Some(err.clone());
        // handle.data_tx is dropped here, closing the channel
    }
}

pub(crate) fn new_mux<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    conn: T,
    cipher: SeqCipher,
    settings: ConnSettings,
    id_offset: u32,
) -> Mux {
    let (read_half, write_half) = tokio::io::split(conn);

    // Clone cipher: one for reading (decrypt), one for writing (encrypt)
    let read_cipher = cipher.clone();
    let write_cipher = cipher;

    let packet_reader = PacketReader::new(read_half, read_cipher, settings.packet_size as usize);
    let packet_writer = PacketWriter::new(write_half, write_cipher, settings.packet_size as usize);

    let (write_tx, write_rx) = mpsc::channel::<WriteCmd>(WRITE_CHANNEL_CAPACITY);
    let (accept_tx, accept_rx) = mpsc::channel::<Stream>(ACCEPT_CHANNEL_CAPACITY);
    let registry = Arc::new(StdMutex::new(StreamRegistry {
        streams: HashMap::new(),
        closing: HashMap::new(),
    }));

    let read_registry = registry.clone();
    let read_write_tx = write_tx.clone();
    let read_handle = tokio::spawn(async move {
        read_loop(
            packet_reader,
            accept_tx,
            read_write_tx,
            read_registry,
            settings,
        )
        .await;
    });

    let write_registry = registry.clone();
    let write_handle = tokio::spawn(async move {
        write_loop(packet_writer, write_rx, write_registry, settings).await;
    });

    Mux {
        write_tx,
        accept_rx: TokioMutex::new(accept_rx),
        next_id: AtomicU32::new(ID_LOWEST_STREAM + id_offset),
        registry,
        settings,
        tasks: TokioMutex::new(Some(TaskHandles {
            read_handle,
            write_handle,
        })),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
            stream.close().await.unwrap();
            accept_mux.close().await.unwrap();
        });

        // Client: write, read echo, close
        let mut stream = dial_mux.dial_stream().unwrap();
        let msg = b"hello, mux!";
        stream.write_all(msg).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        stream.close().await.unwrap();
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
                    stream.close().await.unwrap();
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
                stream.close().await.unwrap();
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

        stream.close().await.unwrap();
        dial_mux.close().await.unwrap();
        accept_handle.await.unwrap();
    }
}
