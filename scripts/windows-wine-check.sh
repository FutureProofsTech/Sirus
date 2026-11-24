#!/usr/bin/env bash
# Windows PE32+ end-to-end runtime check under Wine.
#
# This is a Linux-hosted Win64 validation path. It is intentionally separate
# from the normal verify gate because it requires the Windows Rust target,
# mingw-w64 binutils, lld-link, and Wine.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in rustc wine lld-link x86_64-w64-mingw32-gcc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing Windows/Wine tool: $tool" >&2
        exit 1
    fi
done
if ! rustc --print target-list | grep -qx x86_64-pc-windows-gnu; then
    echo "rust target x86_64-pc-windows-gnu is required" >&2
    exit 1
fi

work="target/windows-wine"
rm -rf "$work"
mkdir -p "$work"

cargo build --release -p sirus-protector >/dev/null
rustc --target x86_64-pc-windows-gnu --edition=2021 \
    -C opt-level=2 -C panic=abort \
    -C linker=x86_64-w64-mingw32-gcc \
    crates/sirus-protector/tests/fixtures/windows_victim.rs \
    -o "$work/victim.exe"

./target/release/sirus protect \
    --input "$work/victim.exe" \
    --output "$work/victim.protected.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/protect.out"
./target/release/sirus protect \
    --input "$work/victim.exe" \
    --output "$work/victim.ct.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --constant-time \
    --constant-time-passes 256 \
    >"$work/protect-ct.out"
chmod +x "$work/victim.protected.exe" "$work/victim.ct.exe"

WINEDEBUG=-all wine "$work/victim.exe" >"$work/native.out" 2>"$work/native.err"
WINEDEBUG=-all wine "$work/victim.protected.exe" >"$work/protected.out" 2>"$work/protected.err"
WINEDEBUG=-all wine "$work/victim.ct.exe" >"$work/constant.out" 2>"$work/constant.err"

for variant in protected constant; do
    if ! cmp -s "$work/native.out" "$work/$variant.out"; then
        echo "Windows/Wine runtime mismatch ($variant)" >&2
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
./target/release/sirus inspect "$work/victim.protected.exe" | tee "$work/inspect.out" >/dev/null
grep -q 'protected=true' "$work/inspect.out"
grep -q '\.sirus' "$work/inspect.out"
echo "PASS Windows/Wine PE32+ runtime (normal + constant-time)"
cat "$work/protect.out"
cat "$work/protect-ct.out"
