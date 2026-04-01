use std::io::{BufRead, stdin};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use clap::Parser;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use sia_storage::{AppMetadata, Builder, DownloadOptions, Object, UploadOptions};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Parser)]
struct Args {
    /// Size of the data to upload and download in bytes (default: 120 MiB)
    #[arg(short, long, default_value_t = 120 * 1024 * 1024)]
    size: usize,
}

const APP_META: AppMetadata = AppMetadata {
    id: sia_storage::app_id!("5c0b1af28e6ac76395b2087ea987297b9c496f90d2ab3e3d3d07980ae4c43633"),
    name: "My Example App",
    description: "My Example App Description",
    service_url: "https://myexampleapp.com",
    logo_url: None,
    callback_url: None,
};

// A reader that produces a deterministic stream of random bytes based on a seed.
struct SeededReader {
    rng: SmallRng,
    remaining: usize,
}

impl SeededReader {
    fn new(seed: u64, size: usize) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(seed),
            remaining: size,
        }
    }
}

impl AsyncRead for SeededReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let n = buf.remaining().min(self.remaining);
        let dst = buf.initialize_unfilled_to(n);
        self.rng.fill_bytes(dst);
        buf.advance(n);
        self.remaining -= n;
        Poll::Ready(Ok(()))
    }
}

struct SeededVerifier {
    rng: SmallRng,
    size: usize,
    remaining: usize,
    start: Instant,
    ttfb: Option<Duration>,
    elapsed: Vec<Duration>,
}

impl SeededVerifier {
    fn new(seed: u64, size: usize) -> Self {
        let now = Instant::now();
        Self {
            rng: SmallRng::seed_from_u64(seed),
            size: size,
            remaining: size,
            start: now,
            ttfb: None,
            elapsed: Vec::new(),
        }
    }

    fn ttfb(&self) -> Option<Duration> {
        self.ttfb
    }

    fn gap_max(&self) -> Option<Duration> {
        if self.elapsed.is_empty() {
            return None;
        }
        self.elapsed.windows(2).map(|w| w[1] - w[0]).max()
    }
}

impl AsyncWrite for SeededVerifier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let now = Instant::now();
        if self.ttfb.is_none() {
            self.ttfb = Some(now - self.start);
        }
        let elapsed = now - self.start;
        let mut expected = vec![0u8; buf.len()];
        self.rng.fill_bytes(&mut expected);
        if buf.len() > self.remaining {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("expected {} more bytes, got {}", self.remaining, buf.len()),
            )));
        }
        if buf != expected.as_slice() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("data mismatch at byte {}", self.size - self.remaining),
            )));
        }
        self.remaining -= buf.len();
        self.elapsed.push(elapsed);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.remaining != 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("expected {} more bytes", self.remaining),
            )));
        }
        Poll::Ready(Ok(()))
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    for &unit in UNITS {
        if value < 1024.0 {
            return format!("{value:.2} {unit}");
        }
        if unit == UNITS[UNITS.len() - 1] {
            return format!("{value:.2} {unit}");
        }
        value /= 1024.0;
    }
    unreachable!()
}

fn format_bitrate(bytes: u64, duration: Duration) -> String {
    let bits_per_sec = (bytes as f64 * 8.0) / duration.as_secs_f64();
    const UNITS: &[&str] = &["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let mut value = bits_per_sec;
    for &unit in UNITS {
        if value < 1000.0 {
            return format!("{value:.2} {unit}");
        }
        if unit == UNITS[UNITS.len() - 1] {
            return format!("{value:.2} {unit}");
        }
        value /= 1000.0;
    }
    unreachable!()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger::init();

    // authorize the app to access the user's storage
    let builder = Builder::new("https://sia.storage", APP_META).expect("failed to create builder");

    let builder = builder
        .request_connection()
        .await
        .expect("failed to request connection");
    println!(
        "Visit the following URL to authorize the application: {}",
        builder.response_url()
    );

    let builder = builder
        .wait_for_approval()
        .await
        .expect("failed to wait for approval");
    println!("Connection approved!");

    println!("Enter recovery phrase:");
    let phrase = stdin()
        .lock()
        .lines()
        .next()
        .expect("failed to read recovery phrase")
        .expect("failed to read recovery phrase");

    let sdk = builder
        .register(&phrase)
        .await
        .expect("failed to register app");
    println!("App registered successfully!");

    let args = Args::parse();
    let seed: u64 = rand::random();

    let reader = SeededReader::new(seed, args.size);

    // upload the data to the network
    println!("Uploading random data...");
    let start = Instant::now();
    let obj = sdk
        .upload(Object::default(), reader, UploadOptions::default())
        .await
        .expect("failed to upload object");
    let upload_duration = start.elapsed();

    // pin the object to ensure it remains available on the network.
    sdk.pin_object(&obj).await.expect("object to be pinned");
    println!("Object pinned successfully!");

    // download the object back from the network
    println!("Downloading object...");
    let start = Instant::now();
    let mut verifier = SeededVerifier::new(seed, args.size);
    sdk.download(&mut verifier, &obj, DownloadOptions::default())
        .await
        .expect("failed to download object");
    let download_duration = start.elapsed();
    println!(
        "Object uploaded ID: {}\tSize: {}\tEncoded: {}\tElapsed: {:?}\tThroughput: {}\tEncoded Throughput: {}",
        obj.id(),
        format_bytes(obj.size()),
        format_bytes(obj.encoded_size()),
        upload_duration,
        format_bitrate(obj.size(), upload_duration),
        format_bitrate(obj.encoded_size(), upload_duration),
    );
    println!(
        "Object downloaded ID: {}\tSize: {}\tEncoded: {}\tElapsed: {:?}\tTTFB: {:?}\tThroughput: {}\tMax Write Latency: {:?}",
        obj.id(),
        format_bytes(obj.size()),
        format_bytes(obj.encoded_size()),
        download_duration,
        verifier.ttfb().unwrap_or_default(),
        format_bitrate(obj.size(), download_duration),
        verifier.gap_max().unwrap_or_default(),
    );
    sdk.delete_object(&obj.id())
        .await
        .expect("failed to delete object");
}
