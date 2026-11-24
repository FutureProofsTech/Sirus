#!/usr/bin/env bash
# Prove that protected output is deterministic for a fixed input and seed.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -p sirus-protector >/dev/null
work="target/reproducible-check"
rm -rf "$work"
mkdir -p "$work"
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    crates/sirus-protector/tests/fixtures/victim.rs -o "$work/victim"

protect() {
    ./target/release/sirus protect \
        --input "$work/victim" \
        --output "$1" \
        --function-contains sirus_demo_check \
        --function-contains sirus_demo_loop \
        --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
        "${@:2}" >/dev/null
}

protect "$work/normal-a"
protect "$work/normal-b"
protect "$work/hardened-a" --hardened
protect "$work/hardened-b" --hardened
protect "$work/ct-a" --constant-time --constant-time-passes 64
protect "$work/ct-b" --constant-time --constant-time-passes 64

for pair in normal hardened ct; do
    if ! cmp -s "$work/$pair-a" "$work/$pair-b"; then
        echo "reproducibility failure: $pair" >&2
        exit 1
    fi
done

sha256sum "$work/normal-a" "$work/hardened-a" "$work/ct-a"
echo "PASS reproducible protected output (normal, hardened, constant-time)"
