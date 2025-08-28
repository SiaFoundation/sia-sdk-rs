use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    let sector = [0u8; 1 << 22];
    c.bench_function("sector_root", |b| {
        b.iter(|| sia::rhp::sector_root(black_box(&sector)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
