use bytes::Bytes;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use sia_core::rhp4::{LEAVES_PER_SECTOR, RangeProof, SECTOR_SIZE};
use std::hint::black_box;

fn sector_root(c: &mut Criterion) {
    let sector = vec![0u8; SECTOR_SIZE];
    let mut group = c.benchmark_group("sector_root");
    group.throughput(Throughput::Bits(SECTOR_SIZE as u64 * 8));
    group.bench_function("sector_root", |b| {
        b.iter(|| sia_core::rhp4::sector_root(black_box(&sector)))
    });
}

fn range_proof_verify(c: &mut Criterion) {
    let sector = Bytes::from(vec![0u8; SECTOR_SIZE]);
    let root = sia_core::rhp4::sector_root(&sector);

    let mut group = c.benchmark_group("range_proof_verify");
    group.throughput(Throughput::Bits(SECTOR_SIZE as u64 * 8));
    group.bench_function("full_sector", |b| {
        b.iter_batched(
            || RangeProof::new(Vec::new(), sector.clone()),
            |proof| {
                proof
                    .verify(black_box(&root), 0, LEAVES_PER_SECTOR)
                    .expect("proof validation failed")
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, sector_root, range_proof_verify);
criterion_main!(benches);
