//! Cross-language interoperability tests between the Rust mux implementation
//! and the Go reference implementation.
//!
//! These tests require the Go interop helper binary to be built first:
//!   cd testutil/go-interop && go build -o interop .
//!
//! The helper binary supports two modes:
//! - `echo-server PORT` — accept one anonymous mux connection and echo all streams
//! - `echo-client ADDR NUM_STREAMS MSG_SIZE` — dial anonymous mux, send/verify echo

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const GO_BINARY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testutil/go-interop/interop");

/// Spawns the Go echo-server and waits for it to print "READY <port>".
/// Returns the child process and the port it's listening on.
fn spawn_go_echo_server() -> (Child, u16) {
    let mut child = Command::new(GO_BINARY)
        .args(["echo-server", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn Go interop binary — did you run `go build -o interop .` in testutil/interop/?");

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read READY line from Go echo-server");

    let port: u16 = line
        .strip_prefix("READY ")
        .expect("expected 'READY <port>' from Go echo-server")
        .trim()
        .parse()
        .expect("invalid port number from Go echo-server");

    // Re-attach stdout so it's not dropped (keeping the pipe open)
    // We don't need it anymore, but dropping it could cause SIGPIPE in the child.
    // Actually, we consumed it. That's fine — the child's stdout is now detached.

    (child, port)
}

// ============================================================================
// Test 1: Go server, Rust client
// ============================================================================

#[tokio::test]
async fn go_server_rust_client_basic_echo() {
    let (mut child, port) = spawn_go_echo_server();
    let addr = format!("127.0.0.1:{port}");

    let conn = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mux = mux::dial_anonymous(conn).await.unwrap();

    let mut stream = mux.dial_stream().unwrap();
    let msg = b"hello from rust to go!";
    stream.write_all(msg).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], msg);

    stream.close().await.unwrap();
    mux.close().await.unwrap();

    // Give the Go process a moment to shut down gracefully
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = child.kill();
    child.wait().ok();
}

#[tokio::test]
async fn go_server_rust_client_many_streams() {
    let (mut child, port) = spawn_go_echo_server();
    let addr = format!("127.0.0.1:{port}");

    let conn = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mux = mux::dial_anonymous(conn).await.unwrap();

    let num_streams = 50;
    let mut handles = Vec::new();

    for i in 0..num_streams {
        let mut stream = mux.dial_stream().unwrap();
        handles.push(tokio::spawn(async move {
            let msg = format!("rust→go stream {i} with some padding data to fill the frame");
            stream.write_all(msg.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(
                &buf[..n],
                msg.as_bytes(),
                "stream {i}: echo mismatch"
            );

            stream.close().await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    mux.close().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = child.kill();
    child.wait().ok();
}

#[tokio::test]
async fn go_server_rust_client_large_payload() {
    let (mut child, port) = spawn_go_echo_server();
    let addr = format!("127.0.0.1:{port}");

    let conn = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mux = mux::dial_anonymous(conn).await.unwrap();

    let mut stream = mux.dial_stream().unwrap();

    // Send a payload larger than one mux packet
    let msg: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    stream.write_all(&msg).await.unwrap();

    // Read it all back
    let mut buf = vec![0u8; msg.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, msg);

    stream.close().await.unwrap();
    mux.close().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = child.kill();
    child.wait().ok();
}

// ============================================================================
// Test 2: Rust server, Go client
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_server_go_client_basic_echo() {
    // Start Rust echo server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mux = mux::accept_anonymous(conn).await.unwrap();

        // Accept and echo streams until the mux closes
        loop {
            match mux.accept_stream().await {
                Ok(mut stream) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = stream.close().await;
                    });
                }
                Err(_) => break,
            }
        }
        let _ = mux.close().await;
    });

    // Spawn Go echo-client (blocking call runs on a separate thread thanks to multi_thread)
    let output = tokio::task::spawn_blocking(move || {
        Command::new(GO_BINARY)
            .args([
                "echo-client",
                &format!("127.0.0.1:{port}"),
                "1",    // 1 stream
                "256",  // 256-byte message
            ])
            .output()
            .expect("failed to spawn Go echo-client")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Go echo-client failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("PASS"),
        "Go echo-client did not report PASS:\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Server task will end when the Go client disconnects
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_server_go_client_many_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mux = mux::accept_anonymous(conn).await.unwrap();

        loop {
            match mux.accept_stream().await {
                Ok(mut stream) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = stream.close().await;
                    });
                }
                Err(_) => break,
            }
        }
        let _ = mux.close().await;
    });

    let output = tokio::task::spawn_blocking(move || {
        Command::new(GO_BINARY)
            .args([
                "echo-client",
                &format!("127.0.0.1:{port}"),
                "50",    // 50 concurrent streams
                "1024",  // 1KB messages
            ])
            .output()
            .expect("failed to spawn Go echo-client")
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Go echo-client failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("PASS"),
        "Go echo-client did not report PASS:\nstdout: {stdout}\nstderr: {stderr}"
    );

    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}
