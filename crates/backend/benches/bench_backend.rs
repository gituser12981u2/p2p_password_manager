use backend::pinset::types::{
    AeadAlgorithm, KeySource, KeyType, PinsetFlags, PinsetHeader, PinsetRecord,
};
use chrono::Utc;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::Rng;
use std::hint::black_box;

//need to use raw identifiers because of the rust keyword gen is now reserved (rand was made for rust 2021, pre-gen keyword)
// We can't  update rand to latest due to some funky dependency issues.
fn create_test_header() -> PinsetHeader {
    let mut rng = rand::thread_rng();
    let store_id: [u8; 16] = rng.r#gen();

    let nonce: [u8; 12] = rng.r#gen();

    PinsetHeader::builder(
        1,
        AeadAlgorithm::AesGcm,
        KeySource::OsKeyStore,
        store_id,
        nonce,
    )
    .seq(42)
    .kdf("argon2id")
    .build()
    .unwrap()
}

// Helper to create a test record
fn create_test_record() -> PinsetRecord {
    let mut rng = rand::thread_rng();
    let peer_id: [u8; 32] = rng.r#gen();
    let key_data = vec![0u8; 32];

    PinsetRecord::new(
        peer_id,
        KeyType::Ed25519,
        key_data,
        Utc::now(),
        PinsetFlags::ACTIVE,
    )
}

fn bench_header_encode(c: &mut Criterion) {
    let header = create_test_header();

    c.bench_function("header_encode", |b| {
        b.iter(|| {
            let encoded = black_box(&header).encode_tlv().unwrap();
            black_box(encoded);
        })
    });
}

fn bench_header_decode(c: &mut Criterion) {
    let header = create_test_header();
    let encoded = header.encode_tlv().unwrap();

    c.bench_function("header_decode", |b| {
        b.iter(|| {
            let decoded = PinsetHeader::decode_tlv(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });
}

fn bench_header_roundtrip(c: &mut Criterion) {
    let header = create_test_header();

    c.bench_function("header_roundtrip", |b| {
        b.iter(|| {
            let encoded = black_box(&header).encode_tlv().unwrap();
            let decoded = PinsetHeader::decode_tlv(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });
}

fn bench_record_encode(c: &mut Criterion) {
    let record = create_test_record();

    c.bench_function("record_encode", |b| {
        b.iter(|| {
            let encoded = black_box(&record).encode_tlv().unwrap();
            black_box(encoded);
        })
    });
}

fn bench_record_decode(c: &mut Criterion) {
    let record = create_test_record();
    let encoded = record.encode_tlv().unwrap();

    c.bench_function("record_decode", |b| {
        b.iter(|| {
            let decoded = black_box(PinsetRecord::decode_tlv(black_box(&encoded)).unwrap());
            black_box(decoded);
        })
    });
}

fn bench_record_roundtrip(c: &mut Criterion) {
    let record = create_test_record();

    c.bench_function("record_roundtrip", |b| {
        b.iter(|| {
            let encoded = black_box(&record).encode_tlv().unwrap();
            let decoded = PinsetRecord::decode_tlv(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });
}

fn bench_record_encode_varying_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("record_encode_key_sizes");

    for key_size in [32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Bytes(*key_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(key_size),
            key_size,
            |b, &size| {
                let mut rng = rand::thread_rng();
                let peer_id: [u8; 32] = rng.r#gen();
                let key_data = vec![0u8; size];
                let record = PinsetRecord::new(
                    peer_id,
                    KeyType::Ed25519,
                    key_data,
                    Utc::now(),
                    PinsetFlags::ACTIVE,
                );

                b.iter(|| {
                    let encoded = black_box(&record).encode_tlv().unwrap();
                    black_box(encoded);
                });
            },
        );
    }
    group.finish();
}

fn bench_record_decode_varying_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("record_decode_key_sizes");

    for key_size in [32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Bytes(*key_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(key_size),
            key_size,
            |b, &size| {
                let mut rng = rand::thread_rng();
                let peer_id: [u8; 32] = rng.r#gen();
                let key_data = vec![0u8; size];
                let record = PinsetRecord::new(
                    peer_id,
                    KeyType::Ed25519,
                    key_data,
                    Utc::now(),
                    PinsetFlags::ACTIVE,
                );
                let encoded = record.encode_tlv().unwrap();

                b.iter(|| {
                    let decoded = PinsetRecord::decode_tlv(black_box(&encoded)).unwrap();
                    black_box(decoded);
                });
            },
        );
    }
    group.finish();
}

fn bench_multiple_records_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_records_encode");

    for count in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &n| {
            let records: Vec<_> = (0..n).map(|_| create_test_record()).collect();

            b.iter(|| {
                let encoded: Vec<_> = records
                    .iter()
                    .map(|r| black_box(r.encode_tlv().unwrap()))
                    .collect();
                black_box(encoded);
            });
        });
    }
    group.finish();
}

fn bench_multiple_records_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_records_decode");

    for count in [10, 50, 100, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &n| {
            let records: Vec<_> = (0..n).map(|_| create_test_record()).collect();
            let encoded: Vec<_> = records.iter().map(|r| r.encode_tlv().unwrap()).collect();

            b.iter(|| {
                let decoded: Vec<_> = encoded
                    .iter()
                    .map(|e| PinsetRecord::decode_tlv(black_box(e)).unwrap())
                    .collect();
                black_box(decoded);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_header_encode,
    bench_header_decode,
    bench_header_roundtrip,
    bench_record_encode,
    bench_record_decode,
    bench_record_roundtrip,
    bench_record_encode_varying_key_sizes,
    bench_record_decode_varying_key_sizes,
    bench_multiple_records_encode,
    bench_multiple_records_decode,
);
criterion_main!(benches);
