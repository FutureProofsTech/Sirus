#!/usr/bin/env bash
# Symbolically execute the generated no_std VM source with KLEE.
#
# KLEE 3.3 consumes LLVM 18 bitcode, so this script builds the generated source
# with rustc 1.78 (LLVM 18). The only source compatibility transform is removing
# `const` from functions: Rust 1.78 cannot const-evaluate mutable-reference
# helpers, while the generated runtime uses the same bodies at run time.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! rustc +1.78.0 --version >/dev/null 2>&1; then
    echo "rustc 1.78.0 is required for LLVM 18 bitcode; run: rustup toolchain install 1.78.0 --profile minimal" >&2
    exit 1
fi
if ! command -v podman >/dev/null 2>&1; then
    echo "podman is required for the KLEE 3.3 image" >&2
    exit 1
fi
if ! podman image exists docker.io/klee/klee:latest; then
    podman pull docker.io/klee/klee:latest
fi

work="target/klee"
rm -rf "$work"
mkdir -p "$work"

cargo build -p sirus-protector >/dev/null
rustc --edition=2021 -C opt-level=2 -C panic=abort \
    crates/sirus-protector/tests/fixtures/victim.rs -o "$work/victim"
./target/debug/sirus protect \
    --input "$work/victim" \
    --output "$work/victim.protected" \
    --function-contains sirus_demo_check \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --emit-source "$work/vm.rs" >"$work/protect.out"

sed -e 's/\bconst fn /fn /g' -e '/^[[:space:]]*reason = /d' "$work/vm.rs" >"$work/vm-klee.rs"
rustc +1.78.0 --edition=2021 --crate-type=lib --emit=llvm-bc \
    -C panic=abort -C opt-level=2 -o "$work/vm.bc" "$work/vm-klee.rs"

# Read the whole symbol table: `awk ... exit` closes the pipe early enough
# that llvm-nm can die with SIGPIPE under `set -o pipefail`.
symbol=$(llvm-nm "$work/vm.bc" | awk '/ T .*sirus_entry/{if (!found) {print $3; found = 1}}')
if [[ -z "$symbol" ]]; then
    echo "entry symbol not found in LLVM bitcode" >&2
    exit 1
fi

cat >"$work/harness.c" <<EOF
#include <stdint.h>
#include <klee/klee.h>
extern uint64_t entry(
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
    __asm__("$symbol");
volatile uint64_t observed;
int main(void) {
    uint64_t a;
    uint64_t b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");
    observed = entry(a, b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}
EOF

seconds="${SIRUS_KLEE_SECONDS:-60}"
set +e
podman run --rm --user root -v "$(pwd)/$work:/work:Z" -w /work \
    docker.io/klee/klee:latest bash -lc "
        clang -emit-llvm -c -O0 -Xclang -disable-O0-optnone harness.c -o harness.bc &&
        llvm-link vm.bc harness.bc -o combined.bc &&
        klee --max-time=$seconds --max-memory=4096 \
             --only-output-states-covering-new combined.bc
    " >"$work/klee.log" 2>&1
status=$?
set -e

if ! grep -q 'KLEE: done: total instructions' "$work/klee.log"; then
    cat "$work/klee.log" >&2
    exit 1
fi
if grep -Eiq 'memory error|out of bounds|invalid read|invalid write|ERROR:' "$work/klee.log"; then
    cat "$work/klee.log" >&2
    echo "KLEE found a memory-safety failure" >&2
    exit 1
fi

summary=$(grep -E 'total instructions|completed paths|partially completed paths|generated tests' "$work/klee.log" | tr '\n' ' ')
echo "$summary" | tee "$work/summary.txt"
echo "PASS KLEE symbolic run (no memory errors in explored paths; exit $status)"
