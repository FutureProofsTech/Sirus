#!/usr/bin/env bash
# Statistical check for the explicit constant-time subset.
set -euo pipefail
cd "$(dirname "$0")/.."

cd verification/dudect
cargo run --release --quiet -- --filter vm_constant 2>&1 | tee ../../target/constant-time-check.out
cd ../..
python3 - <<'PY'
import re
from pathlib import Path

text = Path('target/constant-time-check.out').read_text()
matches = re.findall(
    r'bench (vm_constant\w*)\s+\.\.\.\s*:[^\n]*?max t\s*=\s*([+-]?[0-9.]+)',
    text,
)
if not matches:
    raise SystemExit('constant-time t-test result missing')
values = {name: float(value) for name, value in matches}
required = {'vm_constant', 'vm_constant_branch', 'vm_constant_loop'}
missing = required.difference(values)
if missing:
    raise SystemExit(f'constant-time benchmark missing: {sorted(missing)}')
for name in sorted(values):
    print(f'{name}_max_t={values[name]}')
worst = max(abs(value) for value in values.values())
if worst >= 5.0:
    raise SystemExit(f'constant-time subset exceeded |t| = 5 (worst {worst})')
print(f'PASS constant-time subset below |t| = 5 (worst {worst:.5f})')
PY
