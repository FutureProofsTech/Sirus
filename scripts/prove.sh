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

if [[ "${SIRUS_GHIDRA:-0}" == "1" ]]; then
    echo "== Ghidra headless =="
    ./scripts/ghidra-check.sh
fi

if [[ "${SIRUS_RADARE2:-0}" == "1" ]]; then
    echo "== radare2 pdc =="
    ./scripts/radare2-check.sh
fi

if [[ "${SIRUS_MBA:-0}" == "1" ]]; then
    echo "== GAMBA / SiMBA / MBA-Blast =="
    ./scripts/mba-check.sh
fi

if [[ "${SIRUS_ANGR:-0}" == "1" ]]; then
    echo "== angr symbolic probe =="
    "${SIRUS_ANGR_PYTHON:-/opt/sirus-tools/venv-angr/bin/python}" scripts/angr-check.py
fi

if [[ "${SIRUS_KLEE:-0}" == "1" ]]; then
    echo "== KLEE symbolic VM =="
    ./scripts/klee-check.sh
fi

if [[ "${SIRUS_CREUSOT:-0}" == "1" ]]; then
    echo "== Creusot proofs =="
    ./scripts/creusot-check.sh
fi

if [[ "${SIRUS_DUDECT:-0}" == "1" ]]; then
    echo "== dudect-bencher =="
    ./scripts/dudect-external.sh
fi

if [[ "${SIRUS_CONSTANT_TIME:-0}" == "1" ]]; then
    echo "== constant-time subset =="
    ./scripts/constant-time-check.sh
fi

if [[ "${SIRUS_WINDOWS:-0}" == "1" ]]; then
    echo "== Windows/Wine PE runtime =="
    ./scripts/windows-wine-check.sh
fi

if [[ "${SIRUS_HARDENED:-0}" == "1" ]]; then
    echo "== hardened runtime =="
    ./scripts/hardened-check.sh
fi

echo "== libFuzzer =="
if [[ -d fuzz ]]; then
    (cd fuzz && cargo +nightly fuzz run vm -- -max_total_time="${SIRUS_FUZZ_SECONDS:-20}" -rss_limit_mb=4096 -timeout=5)
fi

if [[ "${SIRUS_REPRODUCIBLE:-0}" == "1" ]]; then
    echo "== reproducible output =="
    ./scripts/reproducible-check.sh
fi

if [[ "${SIRUS_FUZZ_FORMATS:-0}" == "1" ]]; then
    echo "== format fuzzing =="
    (cd fuzz && cargo +nightly fuzz run pe -- -max_total_time="${SIRUS_FUZZ_SECONDS:-20}" -rss_limit_mb=4096 -timeout=5)
    (cd fuzz && cargo +nightly fuzz run elf -- -max_total_time="${SIRUS_FUZZ_SECONDS:-20}" -rss_limit_mb=4096 -timeout=5)
fi

if [[ "${SIRUS_COVERAGE:-0}" == "1" ]]; then
    echo "== coverage =="
    cargo tarpaulin --workspace --all-targets --engine Llvm --out Xml --out Lcov \
        --output-dir target/coverage-all --exclude-files 'target/*' --exclude-files 'bench/*' --timeout 120 --fail-under 85
fi

echo "== proof gates passed =="
