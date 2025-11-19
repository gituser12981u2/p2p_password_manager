#!/usr/bin/env bash
set -euo pipefail

[ "$(basename "$PWD")" != "backend" ] && { echo "Please run from the backend directory  as './scripts/run_benches.sh'"; exit 1; }


# Locate repo root
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Config
BENCH_TARGET="${BENCH_TARGET:-bench_backend}"
RESULTS_DIR="${RESULTS_DIR:-bench_results}"

# Resolve Cargo target dir (honor CARGO_TARGET_DIR if set)
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}"
CRITERION_DIR="$TARGET_DIR/criterion"

# Detect host
OS=$(uname -s | tr '[:upper:]' '[:lower:]')     # linux or darwin
ARCH=$(uname -m)
RUSTV=$(rustc --version | awk '{print $2}')
STAMP=$(date -u +%FT%H-%M-%SZ)
BASELINE="${OS}-${ARCH}-rust${RUSTV}"

OUT="${RESULTS_DIR}/${STAMP}-${OS}-${ARCH}-rust${RUSTV}"
mkdir -p "${OUT}/criterion"

# Metadata
if [[ "$OS" == "linux" ]]; then
  lscpu > "${OUT}/cpu.txt" || true
  uname -a > "${OUT}/kernel.txt"
  cat /etc/os-release > "${OUT}/os.txt" || true
elif [[ "$OS" == "darwin" ]]; then
  sysctl -a | grep machdep.cpu > "${OUT}/cpu.txt" || true
  sw_vers > "${OUT}/os.txt" || true
  uname -a > "${OUT}/kernel.txt"
elif [[ "$OS" == mingw* || "$OS" == msys* ]]; then
  OS="windows"
  uname -a > "${OUT}/kernel.txt"
else
  echo "Unsupported OS: $OS" >&2
  exit 1
fi



cargo build --release

# Run criterion with named baseline
cargo bench --bench "${BENCH_TARGET}" -- --save-baseline "${BASELINE}" "$@"

# Archive criterion outputs
if [[ ! -d "$CRITERION_DIR" ]]; then
  echo "No criterion output at $CRITERION_DIR" >&2
  exit 2
fi

# Copy only the portable artifacts
rsync -a --prune-empty-dirs \
  --filter='- **/new/**' \
  --include '*/' \
  --include 'report/index.html' \
  --include 'estimates.json' \
  --include 'benchmark.json' \
  --include 'raw.csv' \
  --exclude '*' \
  "$CRITERION_DIR/" "${OUT}/criterion/"

echo "Saved to: $(realpath "${OUT}")"
echo "Baseline: $(realpath "${BASELINE}")"
echo "From: $(realpath "${CRITERION_DIR}")"