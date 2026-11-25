#!/usr/bin/env bash
# Cachegrind evidence for the fixed-pass constant-time path.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in valgrind rustc python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing cachegrind tool: $tool" >&2
        exit 1
    fi
done

work="target/cachegrind-ct"
rm -rf "$work"
mkdir -p "$work"

cargo build --release -p sirus-protector >/dev/null
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    bench/constant_time.rs -o "$work/native"

./target/release/sirus protect \
    --input "$work/native" \
    --output "$work/protected" \
    --function-contains sirus_demo_ct \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    --constant-time \
    --constant-time-passes 64 \
    >"$work/protect.out"
chmod +x "$work/protected"

run_case() {
    local name="$1"
    local a="$2"
    local b="$3"
    valgrind \
        --tool=cachegrind \
        --cache-sim=yes \
        --branch-sim=yes \
        --cachegrind-out-file="$work/$name.cachegrind" \
        --log-file="$work/$name.log" \
        "$work/protected" "$a" "$b" 4 >"$work/$name.out"
}

run_case warmup 7 3
run_case forward 7 3
run_case reverse 3 7

python3 - "$work" <<'PY'
import re
import sys
from pathlib import Path

work = Path(sys.argv[1])
fields = {
    'I refs': r'I\s+refs:\s+([0-9,]+)',
    'D refs': r'D\s+refs:\s+([0-9,]+)',
    'D1 misses': r'D1\s+misses:\s+([0-9,]+)',
    'LLd misses': r'LLd\s+misses:\s+([0-9,]+)',
    'Branches': r'Branches:\s+([0-9,]+)',
    'Mispredicts': r'Mispredicts:\s+([0-9,]+)',
}
counts = {}
for name in ('forward', 'reverse'):
    text = (work / f'{name}.log').read_text()
    values = {}
    for field, pattern in fields.items():
        match = re.search(pattern, text)
        if match is None:
            raise SystemExit(f'missing {field} in {name}')
        values[field] = int(match.group(1).replace(',', ''))
    counts[name] = values
for field in fields:
    if counts['forward'][field] != counts['reverse'][field]:
        raise SystemExit(
            f'{field} differs: {counts["forward"][field]} vs {counts["reverse"][field]}'
        )
    print(f'{field}={counts["forward"][field]}')
print('PASS constant-time cachegrind counts are input-independent')
PY

printf '%s\n' "== cachegrind CT =="
cat "$work/protect.out"
