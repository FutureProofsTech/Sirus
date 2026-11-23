#!/usr/bin/env bash
# Live process memory-dump diagnostic. This records a known residual rather
# than pretending the VM's memory-resident registers never contain live values.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in gcore gdb rustc readelf python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required memory-dump tool: $tool" >&2
        exit 1
    fi
done

work="target/memory-dump"
rm -rf "$work"
mkdir -p "$work"
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    crates/sirus-protector/tests/fixtures/memory_victim.rs -o "$work/victim"
./target/debug/sirus protect \
    --input "$work/victim" \
    --output "$work/protected" \
    --function-contains sirus_demo_long \
    --seed 111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000 \
    --fuel 1000000000 >/dev/null
chmod +x "$work/protected"

"$work/protected" 7 20000000 >"$work/out" 2>&1 &
pid=$!
sleep 0.8
gcore -o "$work/core" "$pid" >"$work/gcore.log" 2>&1 || true
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

python3 - "$work/victim" "$work/protected" "$work"/core.* <<'PY'
import struct
import sys
from pathlib import Path

native_path, protected_path, core_path = map(Path, sys.argv[1:])
native = native_path.read_bytes()
protected = protected_path.read_bytes()
core = core_path.read_bytes()

def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def u64(b, o): return struct.unpack_from('<Q', b, o)[0]

def sections(b):
    shoff = u64(b, 0x28); shentsize = u16(b, 0x3a); shnum = u16(b, 0x3c)
    out = []
    for i in range(shnum):
        o = shoff + i * shentsize
        out.append((u32(b, o), u32(b, o + 4), u64(b, o + 24), u64(b, o + 32), u32(b, o + 40), u64(b, o + 56)))
    return out

def functions(b):
    sh = sections(b)
    symtab = next((s for s in sh if s[1] == 2), None)
    if symtab is None:
        return []
    strings = b[sh[symtab[4]][2]:sh[symtab[4]][2] + sh[symtab[4]][3]]
    out = []
    for i in range(symtab[3] // 24):
        o = symtab[2] + i * 24
        name_off = u32(b, o); info = b[o + 4]; value = u64(b, o + 8); size = u64(b, o + 16)
        if info & 0xf != 2 or size == 0:
            continue
        end = strings.find(b'\0', name_off)
        name = strings[name_off:end].decode('utf-8', 'replace')
        if 'sirus_demo_long' in name:
            out.append((value, size))
    return out

def vaddr_to_offset(b, va):
    phoff = u64(b, 0x20); phentsize = u16(b, 0x36); phnum = u16(b, 0x38)
    for i in range(phnum):
        o = phoff + i * phentsize
        if u32(b, o) != 1:
            continue
        off = u64(b, o + 8); vaddr = u64(b, o + 16); filesz = u64(b, o + 32)
        if vaddr <= va < vaddr + filesz:
            return off + va - vaddr
    raise AssertionError('no mapping')

va, size = functions(native)[0]
body = native[vaddr_to_offset(native, va):vaddr_to_offset(native, va) + min(size, 96)]
secret = bytes.fromhex('e0ac6824df9b5713')

if body in core:
    raise SystemExit('FAIL original function body found in live memory')
print('PASS original protected body absent from live memory')
if secret in core:
    print('RESIDUAL sensitive constant observed in transient VM register state')
else:
    print('PASS sensitive constant not observed in this snapshot')
if body in protected:
    raise SystemExit('FAIL original body still present in protected file')
print('PASS original body absent from protected file')
PY
