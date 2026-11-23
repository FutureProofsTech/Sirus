#!/usr/bin/env bash
# Run Creusot/Why3 proofs for the VM boundary models.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! cargo creusot version >/dev/null 2>&1; then
    echo "cargo-creusot is not installed" >&2
    exit 1
fi

CREUSOT_SRC="${SIRUS_CREUSOT_SRC:-$HOME/.local/share/sirus/creusot}"
if [[ ! -f "$CREUSOT_SRC/creusot-std/Cargo.toml" ]]; then
    cat >&2 <<MSG
Creusot source not found at $CREUSOT_SRC.

Install the matching source tree:
  git clone --branch v0.15.0 --depth 1 https://github.com/creusot-rs/creusot.git "\$SIRUS_CREUSOT_SRC"
  sed -i 's/version = "0.15.0"/version = "0.15.0-dev"/g' "\$SIRUS_CREUSOT_SRC"/Cargo.toml "\$SIRUS_CREUSOT_SRC"/creusot-std/Cargo.toml "\$SIRUS_CREUSOT_SRC"/creusot-std-proc/Cargo.toml
  export SIRUS_CREUSOT_SRC

Then rerun this script.
MSG
    exit 1
fi

mkdir -p verification/creusot/.cargo
cat > verification/creusot/.cargo/config.toml <<CONFIG
[patch.crates-io]
creusot-std = { path = "$CREUSOT_SRC/creusot-std" }
CONFIG

cd verification/creusot
cargo creusot
