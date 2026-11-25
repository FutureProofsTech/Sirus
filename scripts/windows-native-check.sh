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

echo "== build protector =="
cargo build --release -p sirus-protector >/dev/null
echo "== harden-check =="
./target/release/sirus.exe harden-check | tee "$work/harden-check.out"
grep -q 'debugger_present=false' "$work/harden-check.out"
grep -q 'debug_registers=0x' "$work/harden-check.out"
echo "== compile C victim =="
x86_64-w64-mingw32-gcc -c \
    crates/sirus-protector/tests/fixtures/windows_abi_xmm.S \
    -o "$work/abi_xmm.o"
x86_64-w64-mingw32-gcc -O2 \
    crates/sirus-protector/tests/fixtures/windows_victim.c \
    "$work/abi_xmm.o" \
    -o "$work/victim.exe"

echo "== protect normal =="
./target/release/sirus.exe protect \
    --input "$work/victim.exe" \
    --output "$work/protected.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --function sirus_abi_target \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/protect.out"

echo "== protect constant-time =="
./target/release/sirus.exe protect \
    --input "$work/victim.exe" \
    --output "$work/constant.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --function sirus_abi_target \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --constant-time \
    --constant-time-passes 256 \
    >"$work/protect-ct.out"

echo "== protect hardened =="
./target/release/sirus.exe protect \
    --input "$work/victim.exe" \
    --output "$work/hardened.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --function sirus_abi_target \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --hardened \
    >"$work/protect-hardened.out"

echo "== run =="
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

python3 scripts/pe-tamper.py "$work/hardened.exe" "$work/tampered.exe"
chmod +x "$work/tampered.exe"
set +e
"$work/tampered.exe" >"$work/tampered.out" 2>"$work/tampered.err"
set -e
if cmp -s "$work/native.out" "$work/tampered.out"; then
    echo "Windows hardened VM accepted modified machine code" >&2
    exit 1
fi
echo "PASS native Windows hardened self-code checksum"

echo "== DLL export =="
x86_64-w64-mingw32-gcc -O2 -shared \
    crates/sirus-protector/tests/fixtures/windows_dll.c \
    -o "$work/dll.dll"
x86_64-w64-mingw32-gcc -O2 \
    crates/sirus-protector/tests/fixtures/windows_dll_host.c \
    -o "$work/dllhost.exe"
cp "$work/dll.dll" "$work/dll.native.dll"
(cd "$work" && ./dllhost.exe >dll.native.out)
./target/release/sirus.exe protect \
    --input "$work/dll.native.dll" \
    --output "$work/dll.protected.dll" \
    --function sirus_dll_fn \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/dll.protect.out"
cp "$work/dll.protected.dll" "$work/dll.dll"
(cd "$work" && ./dllhost.exe >dll.protected.out)
if ! cmp -s "$work/dll.native.out" "$work/dll.protected.out"; then
    echo "Windows DLL runtime mismatch" >&2
    exit 1
fi
echo "PASS native Windows DLL export protection"

echo "== TLS callback and resource =="
x86_64-w64-mingw32-windres \
    crates/sirus-protector/tests/fixtures/windows_tls_resource.rc \
    -O coff -o "$work/tls_resource.o"
x86_64-w64-mingw32-gcc -O2 \
    crates/sirus-protector/tests/fixtures/windows_tls_resource.c \
    "$work/tls_resource.o" -o "$work/tls_resource.exe"
./target/release/sirus.exe protect \
    --input "$work/tls_resource.exe" \
    --output "$work/tls_resource.protected.exe" \
    --function sirus_tls_target \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/tls_resource.protect.out"
"$work/tls_resource.exe" >"$work/tls_resource.native.out"
"$work/tls_resource.protected.exe" >"$work/tls_resource.protected.out"
if ! cmp -s "$work/tls_resource.native.out" "$work/tls_resource.protected.out"; then
    echo "Windows TLS/resource mismatch" >&2
    exit 1
fi
grep -q '^tls-attach' "$work/tls_resource.protected.out"
grep -q '^resource=SIRUSRESOURCE' "$work/tls_resource.protected.out"
echo "PASS native Windows TLS callback and resource preservation"

./target/release/sirus.exe inspect "$work/protected.exe" | tee "$work/inspect.out" >/dev/null
grep -q 'protected=true' "$work/inspect.out"
grep -q '\.sirus' "$work/inspect.out"
echo "PASS native Windows PE32+ runtime (normal + constant-time + hardened)"
cat "$work/protect.out"
cat "$work/protect-ct.out"
