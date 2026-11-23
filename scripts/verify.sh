#!/usr/bin/env bash
# Local release gate for Sirus. No network access is required.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== formatting =="
cargo fmt --all -- --check

echo "== clippy (all targets, warnings denied) =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests =="
cargo test --workspace

echo "== documentation =="
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "== dependency graph =="
cargo tree --workspace --edges normal

echo "== forbidden unsafe constructs =="
if grep -RInE --include='*.rs' '\bunsafe[[:space:]]*\{|#\[unsafe|unsafe fn|unsafe impl|unsafe extern' crates/ ; then
    echo "unsafe construct found" >&2
    exit 1
fi

echo "== all gates passed =="
