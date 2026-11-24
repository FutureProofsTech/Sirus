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
match = re.search(r'vm_constant\s+\.\.\.\s*:.*max t\s*=\s*([+-]?[0-9.]+)', text)
if not match:
    raise SystemExit('constant-time t-test result missing')
value = float(match.group(1))
print(f'constant_time_max_t={value}')
if abs(value) >= 5.0:
    raise SystemExit('constant-time subset exceeded |t| = 5')
print('PASS constant-time subset below |t| = 5')
PY
