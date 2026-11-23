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

if command -v cargo-deny >/dev/null 2>&1; then
    echo "== dependency policy =="
    cargo deny check
fi

if command -v cargo-audit >/dev/null 2>&1; then
    echo "== security advisories =="
    cargo audit
fi

if command -v kani >/dev/null 2>&1; then
    echo "== bounded proofs (Kani) =="
    cargo kani -p sirus-core
    cargo kani -p sirus-vm
else
    echo "kani is required for the proof gate; install via scripts/install-tools.sh" >&2
    exit 1
fi

echo "== documentation =="
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "== dependency graph =="
cargo tree --workspace --edges normal

echo "== forbidden unsafe constructs =="
if grep -RInE --include='*.rs' '\bunsafe[[:space:]]*\{|#\[unsafe|unsafe fn|unsafe impl|unsafe extern' crates/ ; then
    echo "unsafe construct found" >&2
    exit 1
fi

echo "== red-team harness =="
./scripts/red-team.sh

echo "== all gates passed =="
