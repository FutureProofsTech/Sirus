#!/usr/bin/env bash
# Linux caller-saved ABI regression: an optimized caller keeps its loop bound
# in R10 and relies on the callee not clobbering it.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in gcc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing Linux ABI tool: $tool" >&2
        exit 1
    fi
done

work="target/linux-abi"
rm -rf "$work"
mkdir -p "$work"

gcc -O2 -fno-pie -no-pie \
    crates/sirus-protector/tests/fixtures/linux_abi.c \
    -o "$work/native"

for mode in normal hardened constant-time; do
    extra=()
    if [[ "$mode" == "constant-time" ]]; then
        extra=(--constant-time --constant-time-passes 256)
    elif [[ "$mode" == "hardened" ]]; then
        extra=(--hardened)
    fi
    ./target/release/sirus protect \
        --input "$work/native" \
        --output "$work/$mode" \
        --function sirus_abi_loop \
        --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
        "${extra[@]}" \
        >"$work/$mode.protect"
    chmod +x "$work/$mode"
done

"$work/native" 7 3 1 >"$work/native.out"
for mode in normal hardened constant-time; do
    "$work/$mode" 7 3 1 >"$work/$mode.out"
    if ! cmp -s "$work/native.out" "$work/$mode.out"; then
        echo "Linux ABI mismatch ($mode)" >&2
        diff -u "$work/native.out" "$work/$mode.out" >&2
        exit 1
    fi
done
echo "PASS Linux caller-saved ABI regression (normal + hardened + constant-time)"
