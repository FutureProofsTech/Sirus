#!/usr/bin/env bash
# radare2 static/decompiler smoke test on the patched functions.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f target/redteam/protected-a ]]; then
    ./scripts/red-team.sh >/dev/null
fi

work="target/radare2"
rm -rf "$work"
mkdir -p "$work"
binary="target/redteam/protected-a"
out="$work/pdc.txt"

python3 - "$binary" <<'PY' >"$work/addresses.txt"
import subprocess, sys
binary = sys.argv[1]
text = subprocess.check_output(["nm", "-n", binary], text=True)
for line in text.splitlines():
    parts = line.split()
    if len(parts) >= 3 and ("sirus_demo_check" in parts[2] or "sirus_demo_loop" in parts[2]):
        print(parts[0], parts[2])
PY

{
    for entry in $(awk '{print $1}' "$work/addresses.txt"); do
        echo "==== 0x$entry ===="
        r2 -q -e bin.relocs.apply=true -c "aa; s 0x$entry; pdc" "$binary" 2>/dev/null \
            | sed -r 's/\x1b\[[0-9;]*m//g'
    done
} >"$out"

python3 - "$out" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")
blocks = re.split(r'^==== .*? ====$', text, flags=re.M)[1:]
if not blocks:
    raise SystemExit("radare2 produced no function output")
for index, block in enumerate(blocks):
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if not any("goto" in line or "jmp" in line for line in lines):
        raise SystemExit(f"function block {index} does not show a jump/goto")
    logic_markers = ("if (", "while (", "switch (", "for (")
    if any(any(marker in line for marker in logic_markers) for line in lines):
        raise SystemExit("radare2 reconstructed branch logic in a patched function")
print(f"PASS radare2 pdc: {len(blocks)} patched functions show only jump/goto stubs")
Path("target/radare2/summary.txt").write_text(f"functions={len(blocks)} jump_stub=true\n")
PY
