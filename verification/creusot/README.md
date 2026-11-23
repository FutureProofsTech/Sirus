# Creusot proof models

`cargo creusot` discharges the contracts in `src/lib.rs` with Why3, Z3,
Alt-Ergo, CVC4, and CVC5. The models are the exact arithmetic guards used by the
VM and manifest code; they are intentionally isolated because `creusot-std` is
tooling and cannot enter the shipped zero-dependency workspace.

The proved properties are:

- `end_in_bounds` returns true exactly when `start + width <= length`;
- a successful `checked_access` implies `address + width <= memory.len()`;
- `manifest_size(count)` for every accepted count is `Some(count * 16 + 8)`.

Run from the repository root:

```sh
./scripts/creusot-check.sh
```

The local Creusot source must be available via `SIRUS_CREUSOT_SRC` (default
`$HOME/.local/share/sirus/creusot`) and reachable through `cargo creusot`'s
`creusot-std` patch. The script explains the setup when
the toolchain is incomplete.
