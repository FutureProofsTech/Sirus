#!/usr/bin/env bash
# Official dudect-bencher measurement for the cipher and VM branch paths.
set -euo pipefail
cd "$(dirname "$0")/.."
cd verification/dudect
cargo run --release --quiet | tee ../../target/dudect-external.out
