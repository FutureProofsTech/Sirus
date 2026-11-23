#!/usr/bin/env bash
# Installs the external verification tools used by Sirus. Shipped crates remain
# zero-dependency; these tools are development-only.
set -euo pipefail

rustup component add rustfmt clippy llvm-tools rust-src
rustup component add --toolchain nightly miri rust-src llvm-tools

install_if_missing() {
    local command_name="$1"
    local package="$2"
    if command -v "$command_name" >/dev/null 2>&1; then
        echo "present: $command_name"
    else
        cargo install "$package"
    fi
}

install_if_missing cargo-nextest cargo-nextest
install_if_missing cargo-tarpaulin cargo-tarpaulin
install_if_missing cargo-fuzz cargo-fuzz
install_if_missing cargo-audit cargo-audit
install_if_missing cargo-deny cargo-deny
install_if_missing cargo-show-asm cargo-show-asm
install_if_missing kani kani-verifier

echo "optional research tools not auto-installed: Creusot, AORAI, Ghidra, angr, Triton, dudect-bencher, Ferrocene"
