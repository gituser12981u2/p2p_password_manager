#!/usr/bin/env bash

BENCH_DIR=./alloc_benches

mkdir -p $BENCH_DIR

echo "Running standard allocator benchmarks"
cargo bench 
cp -r ../../target/criterion $BENCH_DIR/std_results

echo "Running jemalloc benchmarks..."
cargo bench --features jemallocator
cp -r ../../target/criterion $BENCH_DIR/jemalloc_results


echo "Running mimalloc benchmarks..."
cargo bench --features mimalloc
cp -r ../../target/criterion $BENCH_DIR/mimalloc_results

echo "Running mimalloc secure benchmarks..."
cargo bench --features mimalloc-secure
cp -r ../../target/criterion $BENCH_DIR/mimalloc_secure_results


echo "Running mimalloc v3 benchmarks..."
cargo bench --features mimalloc-v3
cp -r ../../target/criterion $BENCH_DIR/mimalloc_v3_results


echo "Running mimalloc v3 secure benchmarks..."
cargo bench --features mimalloc-v3-secure
cp -r ../../target/criterion $BENCH_DIR/mimalloc_v3_secure_results


echo "Running scudo benchmarks..."
cargo bench --features scudo
cp -r ../../target/criterion $BENCH_DIR/scudo_results


echo "Running snmalloc benchmarks..."
cargo bench --features snmalloc
cp -r ../../target/criterion $BENCH_DIR/snmalloc_results


echo "Running snmalloc secure benchmarks..."
cargo bench --features snmalloc-secure
cp -r ../../target/criterion $BENCH_DIR/snmalloc_secure_results


echo "Running tcmalloc benchmarks..."
cargo bench --features tcmalloc
cp -r ../../target/criterion $BENCH_DIR/tcmalloc_results


echo "Running rpmalloc secure benchmarks..."
echo "PLEASE NOTE, THERE ARE A LOT OF CONFIGURATION OPTIONS ON THIS PACKAGE THAT I HAVENT PUT INTO THE BUILD"
cargo bench --features rpmalloc
cp -r ../../target/criterion $BENCH_DIR/rpmalloc_results


#commented out because this shit broken as hell

# FREEGUARD_PATH=./FreeGuard/libfreeguard.so

# if [ ! -f $FREEGUARD_PATH ]; then
#     echo "Building FreeGuard..."
#     rm -rf FreeGuard
#     git clone https://github.com/UTSASRG/FreeGuard
#     cd FreeGuard
#     make SSE2RNG=1
#     cd ..
# else
#     echo "libfreeguard.so already exists."
# fi
# export LD_PRELOAD=$FREEGUARD_PATH
# LD_PRELOAD="$FREEGUARD_PATH" cargo bench
# cp -r ../../target/criterion $BENCH_DIR/freeguard_results





echo "All benchmarks completed! Results saved to $BENCH_DIR/"
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