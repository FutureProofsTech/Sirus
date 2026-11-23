#!/usr/bin/env bash
# Run Ghidra headless analysis/decompilation on a protected artifact.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -x target/debug/sirus ]]; then
    cargo build -p sirus-protector >/dev/null
fi
if [[ ! -d target/redteam ]]; then
    ./scripts/red-team.sh >/dev/null
fi

GHIDRA_HOME="${GHIDRA_HOME:-/opt/sirus-tools/ghidra_12.2_PUBLIC}"
HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
if [[ ! -x "$HEADLESS" ]]; then
    echo "Ghidra not found at $GHIDRA_HOME; set GHIDRA_HOME" >&2
    exit 1
fi

work="target/ghidra"
rm -rf "$work"
mkdir -p "$work/project"
input="${1:-target/redteam/protected-a}"
out="$work/sirus-decompiled.txt"

"$HEADLESS" "$work/project" Sirus \
    -import "$input" \
    -scriptPath "$(pwd)/scripts/ghidra" \
    -postScript DecompileSirus.java "$(pwd)/$out" \
    -analysisTimeoutPerFile 300 \
    -deleteProject >"$work/headless.log" 2>&1 || true

if [[ ! -s "$out" ]]; then
    echo "Ghidra produced no decompiler output; see $work/headless.log" >&2
    tail -30 "$work/headless.log" >&2
    exit 1
fi

python3 - "$out" "$input" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")
binary = Path(sys.argv[2]).read_bytes()
functions = re.findall(r'^==== (.*?) @ (.*?) ====$', text, re.M)
summary = re.search(r'/\* considered=(\d+) in_sirus=(\d+) completed=(\d+) failed=(\d+) \*/', text)
print("Ghidra scoped functions:", len(functions))
if summary:
    print("Ghidra in_sirus/completed/failed:", summary.group(2), summary.group(3), summary.group(4))
# The protected VM segment should not expose obvious original source names or
# readable source-file strings. Symbols may still include the host function name.
for marker in [b'/src/', b'panicked at', b'index out of bounds', b'vm_entry']:
    if marker in binary:
        print("note: host binary (not scoped .sirus) contains marker", marker)
switch_count = text.count('switch')
case_count = text.count('case ')
long_lines = sum(1 for line in text.splitlines() if len(line) > 200)
print("switch=", switch_count, "case=", case_count, "long_lines=", long_lines)
Path('target/ghidra/summary.txt').write_text(
    f"functions={len(functions)} in_sirus={summary.group(2) if summary else '?'} switch={switch_count} case={case_count} long_lines={long_lines}\n"
)
PY
