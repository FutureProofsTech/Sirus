# Verification-only crates

These crates are intentionally outside the root workspace. They use external
proof/timing tooling and must never enter the shipped zero-dependency graph.

| Directory | Purpose | Command |
|---|---|---|
| `creusot` | Creusot/Why3 proofs of the VM range and manifest-size guards | `./scripts/creusot-check.sh` |
| `dudect` | Official dudect-bencher cipher/VM timing comparison | `./scripts/dudect-external.sh` |

The root `.gitignore` excludes generated proof output, `.cargo` path patches,
and build directories. The scripts pin the local Creusot source through
`SIRUS_CREUSOT_SRC` and never modify the shipped crates.

See `docs/VERIFICATION.md` for the exact results and limitations.
