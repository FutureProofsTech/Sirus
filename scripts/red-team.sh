#!/usr/bin/env bash
# Sirus external red-team harness. Produces artifacts under target/redteam.
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in rustc readelf objcopy strings valgrind timeout python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required red-team tool: $tool" >&2
        exit 1
    fi
done

work="target/redteam"
rm -rf "$work"
mkdir -p "$work"

echo "== building protector and victim =="
cargo build -p sirus-protector >/dev/null
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    crates/sirus-protector/tests/fixtures/victim.rs -o "$work/victim"

echo "== protecting two independent builds =="
seed_a="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
seed_b="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
protect() {
    ./target/debug/sirus protect \
        --input "$work/victim" \
        --output "$1" \
        --function-contains sirus_demo_check \
        --function-contains sirus_demo_loop \
        --seed "$2" >/dev/null
}
protect "$work/protected-a" "$seed_a"
protect "$work/protected-b" "$seed_b"
chmod +x "$work/protected-a" "$work/protected-b"

echo "== native vs protected behavior =="
for args in "7 3" "3 7" "0 0" "123456789 5"; do
    timeout 5 "$work/victim" $args >"$work/native.out"
    timeout 5 "$work/protected-a" $args >"$work/protected.out"
    if ! cmp -s "$work/native.out" "$work/protected.out"; then
        echo "behavior mismatch for arguments: $args" >&2
        exit 1
    fi
done

echo "== structural, entropy, string, differential checks =="
python3 - "$work/victim" "$work/protected-a" "$work/protected-b" <<'PY'
import math
import struct
import sys
from collections import Counter
from pathlib import Path

native_path, protected_a_path, protected_b_path = map(Path, sys.argv[1:])
native = native_path.read_bytes()
protected_a = protected_a_path.read_bytes()
protected_b = protected_b_path.read_bytes()

def u16(data, off): return struct.unpack_from('<H', data, off)[0]
def u32(data, off): return struct.unpack_from('<I', data, off)[0]
def u64(data, off): return struct.unpack_from('<Q', data, off)[0]

class Elf:
    def __init__(self, data):
        assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1
        self.data = data
        self.phoff = u64(data, 0x20)
        self.shoff = u64(data, 0x28)
        self.phentsize = u16(data, 0x36)
        self.phnum = u16(data, 0x38)
        self.shentsize = u16(data, 0x3a)
        self.shnum = u16(data, 0x3c)
        self.shstrndx = u16(data, 0x3e)
        self.phdrs = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            self.phdrs.append({
                'type': u32(data, off), 'flags': u32(data, off + 4),
                'offset': u64(data, off + 8), 'vaddr': u64(data, off + 16),
                'filesz': u64(data, off + 32), 'memsz': u64(data, off + 40),
            })
        self.shdrs = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            self.shdrs.append({
                'name': u32(data, off), 'type': u32(data, off + 4),
                'flags': u64(data, off + 8), 'addr': u64(data, off + 16),
                'offset': u64(data, off + 24), 'size': u64(data, off + 32),
                'link': u32(data, off + 40), 'entsize': u64(data, off + 56),
            })
        self.shstr = b''
        if self.shnum:
            sh = self.shdrs[self.shstrndx]
            self.shstr = data[sh['offset']:sh['offset'] + sh['size']]

    def name(self, index):
        if index >= len(self.shstr):
            return ''
        end = self.shstr.find(b'\0', index)
        return self.shstr[index:end if end >= 0 else len(self.shstr)].decode('utf-8', 'replace')

    def section(self, name):
        for sh in self.shdrs:
            if self.name(sh['name']) == name:
                return sh
        return None

    def section_bytes(self, name):
        sh = self.section(name)
        assert sh is not None, f'missing section {name}'
        return self.data[sh['offset']:sh['offset'] + sh['size']]

    def vaddr_to_offset(self, va):
        for ph in self.phdrs:
            if ph['type'] == 1 and ph['vaddr'] <= va < ph['vaddr'] + ph['filesz']:
                return ph['offset'] + (va - ph['vaddr'])
        raise AssertionError(f'no file offset for {va:#x}')

    def functions(self):
        symtab = None
        for sh in self.shdrs:
            if sh['type'] == 2:
                symtab = sh
                break
        assert symtab is not None, 'no symtab'
        strtab = self.shdrs[symtab['link']]
        strings = self.data[strtab['offset']:strtab['offset'] + strtab['size']]
        count = symtab['size'] // 24
        out = []
        for i in range(count):
            off = symtab['offset'] + i * 24
            name_off = u32(self.data, off)
            info = self.data[off + 4]
            shndx = u16(self.data, off + 6)
            value = u64(self.data, off + 8)
            size = u64(self.data, off + 16)
            if info & 0xf != 2 or shndx == 0 or size == 0:
                continue
            end = strings.find(b'\0', name_off)
            name = strings[name_off:end if end >= 0 else len(strings)].decode('utf-8', 'replace')
            out.append((name, value, size))
        return out

elf_a = Elf(protected_a)
elf_native = Elf(native)
sirus = elf_a.section('.sirus')
payload_a = elf_a.section_bytes('.sirus.payload')
elf_b = Elf(protected_b)
payload_b = elf_b.section_bytes('.sirus.payload')
assert sirus is not None and payload_a, 'missing Sirus sections'
assert elf_a.section('.sirus.payload') is not None
assert len(payload_a) > 1024

loads = [p for p in elf_a.phdrs if p['type'] == 1]
owning = [p for p in loads if p['vaddr'] <= sirus['addr'] < p['vaddr'] + p['memsz']]
assert owning, 'Sirus section is not mapped'
owning = owning[0]
assert owning['flags'] & 1, 'Sirus segment is not executable'
assert owning['flags'] & 2 == 0, 'Sirus segment is writable'
assert sirus['flags'] & 2, 'Sirus section is not allocated'

for function_name in ('sirus_demo_check', 'sirus_demo_loop'):
    matches = [f for f in elf_native.functions() if function_name in f[0]]
    assert len(matches) == 1, f'{function_name} symbol ambiguity'
    name, va, size = matches[0]
    off = elf_a.vaddr_to_offset(va)
    original = native[off:off + size]
    patched = protected_a[off:off + size]
    jump_at = 4 if patched.startswith(b'\xf3\x0f\x1e\xfa') else 0
    assert patched[jump_at] == 0xE9, f'{function_name} not patched'
    changed = sum(1 for a, b in zip(original, patched) if a != b)
    assert changed >= min(size, 8), f'{function_name} body not scrubbed'
    assert protected_a.find(original) < 0, f'{function_name} original body still present in protected file'
    print(f'PASS patch/scrub {function_name}: changed={changed}/{size}; original body absent')

counts = Counter(payload_a)
total = len(payload_a)
entropy = -sum((n / total) * math.log2(n / total) for n in counts.values())
max_ratio = max(counts.values()) / total
min_entropy = -math.log2(max_ratio)
assert entropy > 6.5, f'payload entropy too low: {entropy:.3f}'
assert min_entropy > 3.0, f'payload min-entropy too low: {min_entropy:.3f}'
print(f'PASS payload entropy: shannon={entropy:.3f} min={min_entropy:.3f} distinct={len(counts)}')

text = elf_a.section_bytes('.sirus').decode('latin1')
for marker in ('sirus', 'vm_entry', 'panic', 'rust_begin_unwind', 'core::panicking', '/src/'):
    assert marker not in text, f'leaked string marker in .sirus: {marker}'
print('PASS no obvious strings in injected segment')

common = min(len(payload_a), len(payload_b))
equal = sum(1 for a, b in zip(payload_a[:common], payload_b[:common]) if a == b)
ratio = equal / common if common else 1.0
assert ratio < 0.02, f'differential payloads too similar: {ratio:.4f}'
print(f'PASS differential payload: equal-byte ratio={ratio:.4f} sizes={len(payload_a)}/{len(payload_b)}')
segment_a = elf_a.section_bytes('.sirus')
segment_b = elf_b.section_bytes('.sirus')
segment_common = min(len(segment_a), len(segment_b))
segment_ratio = sum(1 for a, b in zip(segment_a[:segment_common], segment_b[:segment_common]) if a == b) / segment_common
assert segment_ratio < 0.35, f'full VM segment too similar: {segment_ratio:.4f}'
print(f'PASS differential VM segment: equal-byte ratio={segment_ratio:.4f} sizes={len(segment_a)}/{len(segment_b)}')

# Forced-return bypass and payload tamper artifacts.
payload_section = elf_a.section('.sirus.payload')
tampered = bytearray(protected_a)
tampered[payload_section['offset'] + payload_section['size'] // 2] ^= 0x80
Path(protected_a_path.parent / 'tampered').write_bytes(tampered)

matches = [f for f in elf_native.functions() if 'sirus_demo_check' in f[0]]
va = matches[0][1]
off = elf_a.vaddr_to_offset(va)
bypass = bytearray(protected_a)
bypass[off:off + 3] = b'\x31\xc0\xc3'
Path(protected_a_path.parent / 'bypass').write_bytes(bypass)
PY
chmod +x "$work/tampered" "$work/bypass"

timeout 5 "$work/victim" 7 3 >"$work/native.out"
timeout 5 "$work/tampered" 7 3 >"$work/tampered.out" || true
timeout 5 "$work/bypass" 7 3 >"$work/bypass.out" || true
if cmp -s "$work/native.out" "$work/tampered.out"; then
    echo "tampered payload still produced native output" >&2
    exit 1
fi
if cmp -s "$work/native.out" "$work/bypass.out"; then
    echo "forced-return bypass did not alter behavior" >&2
    exit 1
fi
echo "PASS tamper and bypass observably alter results"

if command -v valgrind >/dev/null 2>&1; then
    if ! valgrind --quiet --error-exitcode=99 "$work/protected-a" 7 3 >/dev/null 2>"$work/valgrind.out"; then
        cat "$work/valgrind.out" >&2
        echo "valgrind reported an error" >&2
        exit 1
    fi
    echo "PASS valgrind"
fi

echo "== radare2 decompiler smoke test =="
./scripts/radare2-check.sh

echo "== live memory-dump diagnostic =="
./scripts/memory-dump.sh

echo "== red-team gates passed =="
