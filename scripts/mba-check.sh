#!/usr/bin/env bash
# Run GAMBA/SiMBA/MBA-Blast against the exact post-MBA expression corpus.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/mba-check.py "$@"
