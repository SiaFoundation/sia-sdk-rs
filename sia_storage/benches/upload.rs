use bytes::{Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::Rng;
use sia_core::rhp4::SECTOR_SIZE;
use sia_storage::mock::MockNetwork;
use sia_storage::{AppKey, DownloadOptions, Object, Sdk, UploadOptions};
use std::io::Cursor;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, sink};
use tokio::runtime;

async fn upload_object(sdk: Arc<Sdk>, input: Bytes, opts: UploadOptions) -> Object {
    let r = Cursor::new(input);
    sdk.upload(Object::default(), r, opts)
        .await
        .expect("upload failed")
}

fn upload_benchmark(c: &mut Criterion) {
    let _ = env_logger::builder().is_test(true).try_init();
    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create global runtime");

    let network = MockNetwork::new();
    network.add_hosts(90);

    let sdk = Arc::new(
        runtime
            .block_on(network.sdk(AppKey::import(rand::random())))
            .expect("failed to create sdk"),
    );
    let mut input = BytesMut::zeroed(SECTOR_SIZE * 30); // 3 full slabs
    rand::rng().fill_bytes(&mut input);
    let input = input.freeze();

    let mut large_group = c.benchmark_group("120MiB");
    large_group.throughput(Throughput::Bytes(input.len() as u64));

    // large in-memory slab budget
    large_group.bench_with_input(
        BenchmarkId::new("upload", "90 slabs"),
        &input,
        |b, input| {
            b.to_async(&runtime).iter(|| async {
                upload_object(
                    sdk.clone(),
                    input.clone(),
                    UploadOptions {
                        max_buffered_slabs: Some(90),
                        ..Default::default()
                    },
                )
                .await;
            });
            network.clear_sectors();
        },
    );

    large_group.bench_with_input(
        BenchmarkId::new("upload", "10 slabs"),
        &input,
        |b, input| {
            b.to_async(&runtime).iter(|| async {
                upload_object(
                    sdk.clone(),
                    input.clone(),
                    UploadOptions {
                        max_buffered_slabs: Some(10),
                        ..Default::default()
                    },
                )
                .await;
            });
            network.clear_sectors();
        },
    );

    large_group.bench_with_input(BenchmarkId::new("upload", "default"), &input, |b, input| {
        b.to_async(&runtime).iter(|| async {
            upload_object(sdk.clone(), input.clone(), UploadOptions::default()).await;
        });
        network.clear_sectors();
    });

    let object = runtime.block_on(async {
        upload_object(sdk.clone(), input.clone(), UploadOptions::default()).await
    });

    large_group.bench_with_input(
        BenchmarkId::new("download", "30 chunks"),
        &object,
        |b, object| {
            b.to_async(&runtime).iter(|| async {
                let mut reader = sdk
                    .download(
                        object,
                        DownloadOptions {
                            max_buffered_chunks: Some(30),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                tokio::io::copy(&mut reader, &mut sink())
                    .await
                    .expect("download to complete");
            });
        },
    );

    large_group.bench_with_input(
        BenchmarkId::new("download", "10 chunks"),
        &object,
        |b, object| {
            b.to_async(&runtime).iter(|| async {
                let mut reader = sdk
                    .download(
                        object,
                        DownloadOptions {
                            max_buffered_chunks: Some(10),
                            ..Default::default()
                        },
                    )
                    .unwrap();
                tokio::io::copy(&mut reader, &mut sink())
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
                let mut reader = sdk.download(object, DownloadOptions::default()).unwrap();
                tokio::io::copy(&mut reader, &mut sink())
                    .await
                    .expect("download to complete");
            });
        },
    );

    large_group.finish();

    let mut ttfb_group = c.benchmark_group("ttfb");

    ttfb_group.bench_function("120MiB", |b| {
        b.to_async(&runtime).iter_custom(|iters| {
            let sdk = sdk.clone();
            let object = object.clone();
            async move {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    let mut reader = sdk.download(&object, DownloadOptions::default()).unwrap();
                    let mut buf = [0u8; 1];
                    reader.read_exact(&mut buf).await.expect("read to succeed");
                    total += start.elapsed();
                }
                total
            }
        });
    });

    ttfb_group.bench_function("64B", |b| {
        b.to_async(&runtime).iter_custom(|iters| {
            let sdk = sdk.clone();
            let object = object.clone();
            async move {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    let mut reader = sdk
                        .download(
                            &object,
                            DownloadOptions {
                                length: Some(64),
                                ..Default::default()
                            },
                        )
                        .unwrap();
                    let mut buf = [0u8; 1];
                    reader.read_exact(&mut buf).await.expect("read to succeed");
                    total += start.elapsed();
                }
                total
            }
        });
    });
    ttfb_group.finish();
}

criterion_group!(benches, upload_benchmark);
criterion_main!(benches);
