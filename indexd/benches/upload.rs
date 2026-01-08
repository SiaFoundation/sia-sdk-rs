use bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use indexd::mock::{MockDownloader, MockRHP4Client, MockUploader};
use indexd::{DownloadOptions, Hosts, Object, UploadOptions};
use rand::RngCore;
use sia::rhp::{Host, SECTOR_SIZE};
use sia::signing::PrivateKey;
use sia::types::v2::NetAddress;
use std::io::Cursor;
use std::sync::Arc;
use tokio::io::{AsyncWrite, sink};
use tokio::runtime;

struct TtfbWriter {
    start: std::time::Instant,
    ttfb: Option<std::time::Duration>,
}

impl TtfbWriter {
    fn new(start: std::time::Instant) -> Self {
        Self { start, ttfb: None }
    }

    fn ttfb(&self) -> Option<std::time::Duration> {
        self.ttfb
    }
}

impl AsyncWrite for TtfbWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.ttfb.is_none() {
            self.ttfb = Some(self.start.elapsed());
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

async fn upload_object(uploader: Arc<MockUploader>, input: Bytes, opts: UploadOptions) -> Object {
    let r = Cursor::new(input);
    uploader.upload(r, opts).await.expect("upload failed")
}

fn upload_benchmark(c: &mut Criterion) {
    let app_key = Arc::new(PrivateKey::from_seed(&rand::random()));
    let transport = Arc::new(MockRHP4Client::new());
    let hosts = Hosts::new();
    hosts.update(
        (0..90)
            .map(|_| Host {
                public_key: PrivateKey::from_seed(&rand::random()).public_key(),
                addresses: vec![NetAddress {
                    protocol: sia::types::v2::Protocol::QUIC,
                    address: "localhost:1234".to_string(),
                }],
                country_code: "US".to_string(),
                latitude: 0.0,
                longitude: 0.0,
            })
            .collect(),
    );

    let uploader = Arc::new(MockUploader::new(
        hosts.clone(),
        transport.clone(),
        app_key.clone(),
    ));
    let downloader = Arc::new(MockDownloader::new(
        hosts.clone(),
        transport.clone(),
        app_key.clone(),
    ));
    let mut input = BytesMut::zeroed(SECTOR_SIZE * 30); // 3 full slabs
    rand::rng().fill_bytes(&mut input);
    let input = input.freeze();

    let mut large_group = c.benchmark_group("120MiB");
    large_group.throughput(Throughput::Bytes(input.len() as u64));

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create global runtime");

    // all shards in flight
    large_group.bench_with_input(
        BenchmarkId::new("upload", "90 inflight"),
        &input,
        |b, input| {
            b.to_async(&runtime).iter(|| async {
                upload_object(
                    uploader.clone(),
                    input.clone(),
                    UploadOptions {
                        max_inflight: 90,
                        ..Default::default()
                    },
                )
                .await;
            });
            transport.clear();
        },
    );

    large_group.bench_with_input(
        BenchmarkId::new("upload", "10 inflight"),
        &input,
        |b, input| {
            b.to_async(&runtime).iter(|| async {
                upload_object(
                    uploader.clone(),
                    input.clone(),
                    UploadOptions {
                        max_inflight: 10,
                        ..Default::default()
                    },
                )
                .await;
            });
            transport.clear();
        },
    );

    large_group.bench_with_input(BenchmarkId::new("upload", "default"), &input, |b, input| {
        b.to_async(&runtime).iter(|| async {
            upload_object(uploader.clone(), input.clone(), UploadOptions::default()).await;
        });
        transport.clear();
    });

    let object = runtime.block_on(async {
        upload_object(uploader.clone(), input.clone(), UploadOptions::default()).await
    });

    large_group.bench_with_input(
        BenchmarkId::new("download", "30 inflight"),
        &object,
        |b, object| {
            b.to_async(&runtime).iter(|| async {
                downloader
                    .download(
                        sink(),
                        object,
                        DownloadOptions {
                            max_inflight: 30,
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("download to complete");
            });
        },
    );

    large_group.bench_with_input(
        BenchmarkId::new("download", "10 inflight"),
        &object,
        |b, object| {
            b.to_async(&runtime).iter(|| async {
                downloader
                    .download(
                        sink(),
                        object,
                        DownloadOptions {
                            max_inflight: 10,
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("download to complete");
            });
        },
    );

    large_group.bench_with_input(
        BenchmarkId::new("download", "default"),
        &object,
        |b, object| {
            b.to_async(&runtime).iter(|| async {
                downloader
                    .download(sink(), object, DownloadOptions::default())
                    .await
                    .expect("download to complete");
            });
        },
    );

    large_group.finish();

    let mut ttfb_group = c.benchmark_group("ttfb");

    ttfb_group.bench_function("120MiB", |b| {
        b.to_async(&runtime).iter_custom(|iters| {
            let downloader = downloader.clone();
            let object = object.clone();
            async move {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut w = TtfbWriter::new(std::time::Instant::now());
                    downloader
                        .download(&mut w, &object, DownloadOptions::default())
                        .await
                        .expect("download to complete");
                    total += w.ttfb().unwrap_or_else(|| w.start.elapsed());
                }
                total
            }
        });
    });

    ttfb_group.bench_function("64B", |b| {
        b.to_async(&runtime).iter_custom(|iters| {
            let downloader = downloader.clone();
            let object = object.clone();
            async move {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let mut w = TtfbWriter::new(std::time::Instant::now());
                    downloader
                        .download(
                            &mut w,
                            &object,
                            DownloadOptions {
                                length: Some(64),
                                ..Default::default()
                            },
                        )
                        .await
                        .expect("download to complete");
                    total += w.ttfb().unwrap_or_else(|| w.start.elapsed());
                }
                total
            }
        });
    });
    ttfb_group.finish();
}

criterion_group!(benches, upload_benchmark);
criterion_main!(benches);
