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
install_if_missing cargo-llvm-cov cargo-llvm-cov
install_if_missing kani kani-verifier

echo "Ghidra install used by this host: /opt/sirus-tools/ghidra_12.2_PUBLIC"
echo "radare2 is expected from the distribution"
echo "KLEE: podman pull docker.io/klee/klee:latest; also install rustc 1.78 for LLVM 18"
echo "rustup toolchain install 1.78.0 --profile minimal"
echo "angr: python3.13 -m venv /opt/sirus-tools/venv-angr && /opt/sirus-tools/venv-angr/bin/pip install angr"
echo "MBA tools: clone DenuvoSoftwareSolutions/GAMBA, DenuvoSoftwareSolutions/SiMBA, softsec-unh/MBA-Blast under /opt/sirus-tools"
echo "Creusot: git clone --branch v0.15.0 creusot; patch creusot-std to version 0.15.0-dev; install cargo-creusot"
echo "AORAI is installed with Frama-C but is C-only and not applicable to the Rust product"
echo "optional tools not auto-installed: IDA, Binary Ninja, Ferrocene, Triton, BinDiff/Diaphora"
