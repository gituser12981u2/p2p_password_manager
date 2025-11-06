#!/usr/bin/env bash

BENCH_DIR=./alloc_benches

mkdir -p $BENCH_DIR

echo "Running jemalloc benchmarks..."
cargo bench --features jemallocator
cp -r ../../target/criterion $BENCH_DIR/jemalloc_results


echo "Running mimalloc benchmarks..."
cargo bench --features mimalloc
cp -r ../../target/criterion $BENCH_DIR/mimalloc_results

echo "Running mimalloc secure benchmarks..."
cargo bench --features mimalloc-secure
cp -r ../../target/criterion $BENCH_DIR/mimalloc_secure_results


echo "Running scudo benchmarks..."
cargo bench --features scudo
cp -r ../../target/criterion $BENCH_DIR/scudo_results


echo "Running snmalloc benchmarks..."
cargo bench --features snmalloc
cp -r ../../target/criterion $BENCH_DIR/snmalloc_results

echo "All benchmarks completed! Results saved to $BENCH_DIR/"