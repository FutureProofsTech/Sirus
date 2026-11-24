#!/usr/bin/env bash
# Local proof for the optional unsafe hardened tier.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -p sirus-protector >/dev/null
sirus=./target/release/sirus
work=target/hardened-check
rm -rf "$work"
mkdir -p "$work"

"$sirus" harden-check | tee "$work/harden-check.out"
grep -q 'debugger_present=false' "$work/harden-check.out"
grep -q 'debug_registers=unsupported' "$work/harden-check.out"

rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    crates/sirus-protector/tests/fixtures/victim.rs -o "$work/victim"
"$sirus" protect \
    --input "$work/victim" \
    --output "$work/hardened" \
    --function-contains sirus_demo_check \
    --function-contains sirus_demo_loop \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --hardened >"$work/protect.out"
chmod +x "$work/hardened"

"$work/victim" 7 3 >"$work/native.out"
"$work/hardened" 7 3 >"$work/normal.out"
cmp "$work/native.out" "$work/normal.out"

if command -v strace >/dev/null 2>&1; then
    strace -f -o /dev/null "$sirus" harden-check | tee "$work/harden-check-traced.out"
    grep -q 'debugger_present=true' "$work/harden-check-traced.out"
    strace -f -o /dev/null "$work/hardened" 7 3 >"$work/traced.out"
    if cmp -s "$work/native.out" "$work/traced.out"; then
        echo "hardened binary did not reject the tracer" >&2
        exit 1
    fi
    grep -q '^0$' "$work/traced.out"
else
    echo "strace unavailable; traced-runtime positive check skipped"
fi

"$sirus" protect \
    --input "$work/victim" \
    --output "$work/timing" \
    --function-contains sirus_demo_check \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --hardened \
    --hardened-timing-cycles 1 >"$work/protect-timing.out"
chmod +x "$work/timing"
"$work/timing" 7 3 >"$work/timing.out"
first=$(head -n 1 "$work/timing.out")
if [[ "$first" != "0" ]]; then
    echo "hardened timing check did not reject the call" >&2
    cat "$work/timing.out" >&2
    exit 1
fi

if command -v wine >/dev/null 2>&1; then
    cargo build --release --target x86_64-pc-windows-gnu -p sirus-protector >/dev/null
    WINEDEBUG=-all wine target/x86_64-pc-windows-gnu/release/sirus.exe harden-check \
        | tee "$work/windows-harden-check.out"
    grep -q 'debugger_present=false' "$work/windows-harden-check.out"
    grep -q 'debug_registers=0x' "$work/windows-harden-check.out"
else
    echo "wine unavailable; Windows debug-register check skipped"
fi

echo "PASS hardened runtime checks (anti-debug + RDTSC + LFENCE)"
cat "$work/normal.out"
