#!/usr/bin/env bash
# Long-form proof gates. These are deliberately separate from the fast verify gate.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Kani =="
cargo kani -p sirus-core
cargo kani -p sirus-vm

echo "== Miri (core and VM unit tests) =="
cargo +nightly miri test -p sirus-core
cargo +nightly miri test -p sirus-vm --lib

if [[ "${SIRUS_FULL_MIRI:-0}" == "1" ]]; then
    echo "== Miri (full VM integration, slow) =="
    cargo +nightly miri test -p sirus-vm --test execution
fi

echo "== libFuzzer =="
if [[ -d fuzz ]]; then
    (cd fuzz && cargo +nightly fuzz run vm -- -max_total_time="${SIRUS_FUZZ_SECONDS:-20}" -rss_limit_mb=4096 -timeout=5)
fi

if [[ "${SIRUS_COVERAGE:-0}" == "1" ]]; then
    echo "== coverage =="
    cargo tarpaulin --workspace --all-targets --engine Llvm --out Xml --out Lcov \
        --output-dir target/coverage-all --timeout 120
fi

echo "== proof gates passed =="
