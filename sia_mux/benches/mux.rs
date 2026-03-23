use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sia_mux::{ConnSettings, IPV6_MTU, Mux};
use tokio::io::{AsyncWriteExt, copy, sink};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

async fn new_testing_pair() -> (Mux, Mux) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_fut = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        conn.set_nodelay(true).unwrap();
        sia_mux::accept_anonymous(conn).await.unwrap()
    });

    let dial_conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    dial_conn.set_nodelay(true).unwrap();
    let dial_mux = sia_mux::dial_anonymous(dial_conn).await.unwrap();
    let accept_mux = accept_fut.await.unwrap();

    (dial_mux, accept_mux)
}

async fn new_testing_pair_with_settings(settings: ConnSettings) -> (Mux, Mux) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let accept_fut = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        conn.set_nodelay(true).unwrap();
        sia_mux::accept_anonymous_with_settings(conn, settings)
            .await
            .unwrap()
    });

    let dial_conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    dial_conn.set_nodelay(true).unwrap();
    let dial_mux = sia_mux::dial_anonymous_with_settings(dial_conn, settings)
        .await
        .unwrap();
    let accept_mux = accept_fut.await.unwrap();

    (dial_mux, accept_mux)
}

/// Spawn a task that accepts streams and discards all data.
fn spawn_discard_server(rt: &Runtime, mux: Mux) {
    rt.spawn(async move {
        loop {
            let Ok(mut stream) = mux.accept_stream().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = copy(&mut stream, &mut sink()).await;
            });
        }
    });
}

fn bench_mux(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create runtime");

    let buf_size = ConnSettings::default().max_payload_size();

    for num_streams in [1, 2, 10, 100, 500, 1000] {
        let mut group = c.benchmark_group("mux");
        group.throughput(Throughput::BytesDecimal((buf_size * num_streams) as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(num_streams),
            &num_streams,
            |b, &num_streams| {
                let (dial_mux, accept_mux) = runtime.block_on(new_testing_pair());
                spawn_discard_server(&runtime, accept_mux);

                let buf = vec![0u8; buf_size];

                b.iter(|| {
                    runtime.block_on(async {
                        let mut handles = Vec::with_capacity(num_streams);
                        for _ in 0..num_streams {
                            let mut stream = dial_mux.dial_stream().unwrap();
                            let buf = buf.clone();
                            handles.push(tokio::spawn(async move {
                                stream.write_all(&buf).await.unwrap();
                            }));
                        }
                        for h in handles {
                            h.await.unwrap();
                        }
                    });
                });

                runtime.block_on(async {
                    let _ = dial_mux.close().await;
                });
            },
        );

        group.finish();
    }
}

fn bench_packets(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create runtime");

    let mut group = c.benchmark_group("packets");

    for multiplier in [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20] {
        let settings =
            ConnSettings::new(IPV6_MTU * multiplier, ConnSettings::default().max_timeout())
                .unwrap();
        let buf_size = settings.max_payload_size();
        group.throughput(Throughput::BytesDecimal(buf_size as u64));

        group.bench_with_input(
            BenchmarkId::new(format!("{IPV6_MTU}x{multiplier}"), buf_size),
            &buf_size,
            |b, &buf_size| {
                let (dial_mux, accept_mux) =
                    runtime.block_on(new_testing_pair_with_settings(settings));
                spawn_discard_server(&runtime, accept_mux);
                let mut stream = runtime.block_on(async {
                    let mut s = dial_mux.dial_stream().unwrap();
                    s.write_all(&[0u8]).await.unwrap();
                    s
                });
                let buf = vec![0u8; buf_size];

                b.iter(|| {
                    runtime.block_on(async {
                        stream.write_all(&buf).await.unwrap();
                    });
                });

                runtime.block_on(async {
                    let _ = stream.close();
                    let _ = dial_mux.close().await;
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_mux, bench_packets);
criterion_main!(benches);
