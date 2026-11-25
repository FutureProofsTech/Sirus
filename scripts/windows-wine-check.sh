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
./target/release/sirus protect \
    --input "$work/victim.exe" \
    --output "$work/victim.hardened.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --hardened \
    >"$work/protect-hardened.out"
./target/release/sirus protect \
    --input "$work/victim.exe" \
    --output "$work/victim.hardened.ct.exe" \
    --function sirus_win_check \
    --function sirus_win_mix \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --hardened \
    --constant-time \
    --constant-time-passes 256 \
    >"$work/protect-hardened-ct.out"
chmod +x "$work/victim.protected.exe" "$work/victim.ct.exe" "$work/victim.hardened.exe" "$work/victim.hardened.ct.exe"

WINEDEBUG=-all wine "$work/victim.exe" >"$work/native.out" 2>"$work/native.err"
WINEDEBUG=-all wine "$work/victim.protected.exe" >"$work/protected.out" 2>"$work/protected.err"
WINEDEBUG=-all wine "$work/victim.ct.exe" >"$work/constant.out" 2>"$work/constant.err"
WINEDEBUG=-all wine "$work/victim.hardened.exe" >"$work/hardened.out" 2>"$work/hardened.err"
WINEDEBUG=-all wine "$work/victim.hardened.ct.exe" >"$work/hardened-ct.out" 2>"$work/hardened-ct.err"

for variant in protected constant hardened hardened-ct; do
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
echo "PASS Windows/Wine PE32+ runtime (normal + constant-time + hardened)"
cat "$work/protect.out"
cat "$work/protect-ct.out"
cat "$work/protect-hardened.out"
cat "$work/protect-hardened-ct.out"

echo "== C ABI matrix =="
fixtures="crates/sirus-protector/tests/fixtures"
x86_64-w64-mingw32-gcc -c "$fixtures/windows_abi_xmm.S" -o "$work/abi_xmm.o"
x86_64-w64-mingw32-gcc -O2 "$fixtures/windows_victim.c" "$work/abi_xmm.o" \
    -o "$work/cvictim.exe"
for variant in normal ct hardened; do
    extra=()
    if [[ "$variant" == "ct" ]]; then
        extra=(--constant-time --constant-time-passes 128)
    elif [[ "$variant" == "hardened" ]]; then
        extra=(--hardened)
    fi
    ./target/release/sirus protect \
        --input "$work/cvictim.exe" \
        --output "$work/cvictim.$variant.exe" \
        --function sirus_win_check \
        --function sirus_win_mix \
        --function sirus_abi_target \
        --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
        "${extra[@]}" \
        >"$work/cvictim.$variant.protect"
    chmod +x "$work/cvictim.$variant.exe"
done
WINEDEBUG=-all wine "$work/cvictim.exe" >"$work/cvictim.native.out" 2>"$work/cvictim.native.err"
for variant in normal ct hardened; do
    WINEDEBUG=-all wine "$work/cvictim.$variant.exe" \
        >"$work/cvictim.$variant.out" 2>"$work/cvictim.$variant.err"
    if ! cmp -s "$work/cvictim.native.out" "$work/cvictim.$variant.out"; then
        echo "C ABI mismatch ($variant)" >&2
        diff -u "$work/cvictim.native.out" "$work/cvictim.$variant.out" >&2
        exit 1
    fi
done
grep -q 'abi 48 48 0 3' "$work/cvictim.native.out"
echo "PASS Windows/Wine C ABI matrix (XMM6-15, indirect, large frame)"

python3 scripts/pe-tamper.py \
    "$work/cvictim.hardened.exe" "$work/cvictim.tampered.exe"
chmod +x "$work/cvictim.tampered.exe"
set +e
WINEDEBUG=-all wine "$work/cvictim.tampered.exe" \
    >"$work/cvictim.tampered.out" 2>"$work/cvictim.tampered.err"
set -e
if cmp -s "$work/cvictim.native.out" "$work/cvictim.tampered.out"; then
    echo "Windows/Wine hardened VM accepted modified machine code" >&2
    exit 1
fi
echo "PASS Windows/Wine hardened self-code checksum"

echo "== DLL export =="
x86_64-w64-mingw32-gcc -O2 -shared "$fixtures/windows_dll.c" -o "$work/dll.dll"
x86_64-w64-mingw32-gcc -O2 "$fixtures/windows_dll_host.c" -o "$work/dllhost.exe"
cp "$work/dll.dll" "$work/dll.native.dll"
(cd "$work" && WINEDEBUG=-all wine dllhost.exe >dll.native.out)
./target/release/sirus protect \
    --input "$work/dll.native.dll" \
    --output "$work/dll.protected.dll" \
    --function sirus_dll_fn \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/dll.protect.out"
cp "$work/dll.protected.dll" "$work/dll.dll"
(cd "$work" && WINEDEBUG=-all wine dllhost.exe >dll.protected.out)
if ! cmp -s "$work/dll.native.out" "$work/dll.protected.out"; then
    echo "Windows/Wine DLL runtime mismatch" >&2
    exit 1
fi
echo "PASS Windows/Wine DLL export protection"

echo "== TLS callback and resource =="
x86_64-w64-mingw32-windres "$fixtures/windows_tls_resource.rc" \
    -O coff -o "$work/tls_resource.o"
x86_64-w64-mingw32-gcc -O2 "$fixtures/windows_tls_resource.c" \
    "$work/tls_resource.o" -o "$work/tls_resource.exe"
./target/release/sirus protect \
    --input "$work/tls_resource.exe" \
    --output "$work/tls_resource.protected.exe" \
    --function sirus_tls_target \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    >"$work/tls_resource.protect.out"
(cd "$work" && WINEDEBUG=-all wine tls_resource.exe >tls_resource.native.out)
(cd "$work" && WINEDEBUG=-all wine tls_resource.protected.exe >tls_resource.protected.out)
if ! cmp -s "$work/tls_resource.native.out" "$work/tls_resource.protected.out"; then
    echo "Windows/Wine TLS/resource mismatch" >&2
    exit 1
fi
grep -q '^tls-attach' "$work/tls_resource.protected.out"
grep -q '^resource=SIRUSRESOURCE' "$work/tls_resource.protected.out"
echo "PASS Windows/Wine TLS callback and resource preservation"
