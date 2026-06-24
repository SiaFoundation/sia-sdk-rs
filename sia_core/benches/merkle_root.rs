use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sia_core::rhp4::SECTOR_SIZE;
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    let sector = vec![0u8; 1 << 22];
    let mut group = c.benchmark_group("sector_root");
    group.throughput(Throughput::Bits(SECTOR_SIZE as u64 * 8));
    group.bench_function("sector_root", |b| {
        b.iter(|| sia_core::rhp4::sector_root(black_box(&sector)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
