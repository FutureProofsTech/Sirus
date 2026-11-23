#!/usr/bin/env bash
# Statistical timing measurement for the constant-time cipher path and the
# deliberately data-dependent VM branch path.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo test -p sirus-vm --test timing --release -- --ignored --nocapture 2>&1 \
    | tee target/dudect.out

if ! grep -q 'DUDECT ' target/dudect.out; then
    echo "dudect measurement did not produce a result" >&2
    exit 1
fi
