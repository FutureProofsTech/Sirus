#!/usr/bin/env bash
# Native Windows PE32+ end-to-end runtime check.
#
# Run on a Windows host with the x86_64-pc-windows-gnu target, mingw-w64, and
# lld-link in PATH. The GitHub Windows-native job is staged but has not been
# executed locally; the Wine script is the executed Linux-hosted gate.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in rustc x86_64-w64-mingw32-gcc lld-link; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing Windows tool: $tool" >&2
        exit 1
    fi
done
if ! rustc --print target-list | grep -qx x86_64-pc-windows-gnu; then
    echo "rust target x86_64-pc-windows-gnu is required" >&2
    exit 1
fi

work="target/windows-native"
rm -rf "$work"
mkdir -p "$work"

cargo build --release -p sirus-protector >/dev/null
./target/release/sirus.exe harden-check | tee "$work/harden-check.out"
grep -q 'debugger_present=false' "$work/harden-check.out"
grep -q 'debug_registers=0x' "$work/harden-check.out"
rustc --target x86_64-pc-windows-gnu --edition=2021 \
    -C opt-level=2 -C panic=abort \
    -C linker=x86_64-w64-mingw32-gcc \
    crates/sirus-protector/tests/fixtures/windows_victim.rs \
    -o "$work/victim.exe"

./target/release/sirus.exe protect \
    --input "$work/victim.exe" \
    --output "$work/protected.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/protect.out"

./target/release/sirus.exe protect \
    --input "$work/victim.exe" \
    --output "$work/constant.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --constant-time \
    --constant-time-passes 256 \
    >"$work/protect-ct.out"

./target/release/sirus.exe protect \
    --input "$work/victim.exe" \
    --output "$work/hardened.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --hardened \
    >"$work/protect-hardened.out"

"$work/victim.exe" >"$work/native.out" 2>"$work/native.err"
"$work/protected.exe" >"$work/protected.out" 2>"$work/protected.err"
"$work/constant.exe" >"$work/constant.out" 2>"$work/constant.err"
"$work/hardened.exe" >"$work/hardened.out" 2>"$work/hardened.err"

for variant in protected constant hardened; do
    if ! cmp -s "$work/native.out" "$work/$variant.out"; then
        echo "Windows runtime mismatch ($variant)" >&2
        echo "native:" >&2
        cat "$work/native.out" >&2
        echo "$variant:" >&2
        cat "$work/$variant.out" >&2
        exit 1
    fi
    if [[ ! -s "$work/$variant.out" ]]; then
        echo "$variant Windows binary produced no output" >&2
        exit 1
    fi
done
./target/release/sirus.exe inspect "$work/protected.exe" | tee "$work/inspect.out" >/dev/null
grep -q 'protected=true' "$work/inspect.out"
grep -q '\.sirus' "$work/inspect.out"
echo "PASS native Windows PE32+ runtime (normal + constant-time + hardened)"
cat "$work/protect.out"
cat "$work/protect-ct.out"
