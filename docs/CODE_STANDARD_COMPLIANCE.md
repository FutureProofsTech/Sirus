# Code Standard Compliance Matrix

**Snapshot:** current working tree. This document states
what is enforced now, what is intentionally deferred, and what is impossible
under the project's zero-unsafe/no-runtime-dependency constraints. It must be
updated whenever a lint tier, test exemption, or tool gate changes.

---

## 1. Tier model

The supplied standard assumes one homogeneous codebase. Sirus has three runtime
tiers with different capabilities. Applying the wrong tier would force either
unsafe code or false claims, so the standard is applied by tier:

| Tier | Crates | `no_std` | Allocation | `std` | Unsafe | Level 2 core isolation |
|---|---|---:|---:|---:|---:|---|
| A — compiler core | `sirus-core` | yes | no | no | forbidden | full |
| A — injected runtime | `sirus-vm` | yes | no | no | forbidden | full |
| B — build-time binary tooling | `sirus-binfmt` | yes | intentional `alloc` | no | forbidden | partial: `std_instead_of_core` only |
| C — build-time CLI/orchestration | `sirus-protector` | no (filesystem/process boundary) | intentional | yes | forbidden | waived, all other levels enforced |

Tier C is a thin process/filesystem boundary. All protection logic lives in
Tier A or B crates. Implementing Tier C as `no_std` without unsafe FFI is not
possible, and introducing unsafe FFI would violate the higher-priority
zero-unsafe requirement. This is a recorded design decision, not an accident.

---

## 2. Level 1 — deny default lax patterns

Enforced in all four crates:

- `clippy::all = deny`
- `clippy::pedantic = deny`
- `clippy::nursery = deny`
- `clippy::cargo = deny`

Evidence:

- `Cargo.toml` workspace lint table for Tier A/B.
- `crates/sirus-protector/Cargo.toml` explicit Tier C lint table.
- Crate-level `#![deny(...)]` blocks in every shipped crate.
- `cargo clippy --workspace --all-targets -- -D warnings` is the gate.

**Status: enforced.**

---

## 3. Level 2 — core ecosystem isolation

### Tier A (`sirus-core`, `sirus-vm`)

- `#![no_std]`
- no `alloc`
- no `std`
- `clippy::alloc_instead_of_core = deny`
- `clippy::std_instead_of_core = deny`
- `clippy::std_instead_of_alloc = deny`
- no heap data structures in the compiler or VM; fixed-capacity arrays only.

**Status: fully enforced.**

### Tier B (`sirus-binfmt`)

- `#![no_std]`
- `alloc` is used only for parsed header vectors, symbol vectors, and edited
  output images at build time.
- `clippy::std_instead_of_core = deny`
- `clippy::alloc_instead_of_core` and `std_instead_of_alloc` are intentionally
  not applied because binary parsing and rewriting require owned vectors.
- no `std` filesystem/process access in this crate.

**Status: partial by documented design.**

### Tier C (`sirus-protector`)

- Uses `std` exclusively for CLI, filesystem, process execution, and temporary
  directories.
- Safe Rust only.
- All Level 1, 3, 4, 5 lints apply.
- Level 2 is waived with this justification: a post-link injector must read and
  write files and launch `rustc`; doing that from `no_std` requires unsafe
  syscalls or a C library, both forbidden.

**Status: waived with justification; all other levels apply.**

---

## 4. Level 3 — zero runtime panic matrices

Production code (all tiers):

- `clippy::unwrap_used = deny`
- `clippy::expect_used = deny`
- `clippy::indexing_slicing = deny`
- `clippy::panic = deny`
- `clippy::todo = deny`
- `clippy::unimplemented = deny`
- `clippy::unreachable = deny`
- `#![forbid(unsafe_code)]`

**Test-only exemption (explicit, scoped):**

`#[cfg(test)]` code allows `expect`, `unwrap`, fixed-index access, and
`panic`-based assertions. This is required by Rust's test harness and fixed test
vectors; it does not affect shipped code. The exemption is declared at crate
root with a reason and applies only to test builds. Integration test crates
carry the same explicit allow with the same reason.

The verification script additionally rejects `unsafe` constructs across all
`.rs` files. Clippy is the authoritative gate for panic-family lints in
production builds.

**Status: enforced for shipped code; scoped test exemption documented.**

---

## 5. Level 4 — bit-level security and anti-side-channel casting

Enforced in all four crates:

- `clippy::as_conversions = deny`
- `clippy::cast_lossless = deny`
- `clippy::cast_possible_truncation = deny`
- `clippy::cast_possible_wrap = deny`
- `clippy::float_arithmetic = deny`

All integer conversions use `From`, `TryFrom`, checked arithmetic, or explicit
bit reinterpretation via `to_ne_bytes`/`from_ne_bytes`. No floating point exists
in shipped code.

**Status: enforced.**

---

## 6. Level 5 — restructuring and memory tracking

Enforced in Tier A/B, and in Tier C production code:

- `clippy::missing_inline_in_public_items = deny`
- `clippy::exhaustive_structs = deny`

Public structs are `#[non_exhaustive]` or private. Public callables carry
`#[inline]` where the lint applies.

**Status: enforced.**

---

## 7. Paranoia additions beyond the supplied list

Additional enforced lints:

- `missing_docs = deny`
- `missing_debug_implementations = deny`
- `unused_qualifications`, `trivial_numeric_casts`, `unused_lifetimes`,
  `single_use_lifetimes`, `let_underscore_drop`, `non_ascii_idents`,
  `meta_variable_misuse`
- Clippy: `exit`, `print_stdout`, `print_stderr`, `dbg_macro`, `mem_forget`,
  `panic_in_result_fn`
- `clippy::large_stack_arrays` / `large_stack_frames` / `too_many_lines` are
  allowed at crate level with a documented reason because the core deliberately
  uses fixed-capacity state machines with no allocation and no hidden heap.

**Status: enforced.**

---

## 8. Cargo release profile

Implemented exactly in the root `Cargo.toml`:

| Requirement | Value | Status |
|---|---|---|
| `opt-level` | `3` | enforced |
| `lto` | `true` | enforced |
| `codegen-units` | `1` | enforced |
| `panic` | `abort` | enforced |
| `strip` | `true` | enforced |
| overflow checks | off in release | additional hardening |

**Status: enforced.**

---

## 9. Verification tooling

### Installed and available locally

| Tool | Availability | Gate status |
|---|---|---|
| `cargo fmt` | stable | executed, passing |
| `cargo clippy` | stable | executed with `-D warnings`, passing |
| `cargo test` | stable | executed, passing |
| `cargo doc` | stable | executed with `-D warnings`, passing |
| `cargo-audit` | installed | executed; 0 vulnerabilities |
| `cargo-deny` | installed | executed; advisories/bans/licenses/sources pass |
| `cargo-nextest` | installed | executed; 145/145 tests |
| `cargo-tarpaulin` | installed | executed; 87.64% lines, 100% target not met |
| `cargo-fuzz` | installed | 66,962 runs, no crash |
| Kani 0.68.0 | installed | 5 core + 2 VM harnesses verified |
| Miri | nightly | core and VM unit/execution suites pass |
| valgrind | installed | protected sample clean |
| gdb/strace/perf | installed | available; no scripted gate yet |
| cargo-show-asm | installed | used for assembly inspection |
| Creusot | **missing** | install required |
| AORAI | **missing** | research tool; optional |
| Ferrocene | **missing** | optional certified toolchain |
| Ghidra/angr/Triton | **missing** | optional red-team tooling |
| dudect-bencher | **missing** | in-tree timing harness planned; external optional |

### Not yet satisfied gates

These remain open, not claimed:

1. 100% coverage: measured 87.64% line coverage; uncovered defensive branches are
   enumerated from LCOV.
2. Full red-team external tooling: Ghidra/IDA/Binary Ninja, GAMBA/SiMBA, angr/KLEE,
   Creusot, AORAI, Ferrocene, dudect-style timing.
3. Live process memory-dump scanner.
4. Full handler-layout mutation across builds (full `.sirus` equality 25.2%).
5. Windows PE runtime execution and Win64 ABI validation.

All protector modules are now wired into the crate and included in the Clippy
graph. **No release claim may be made while any item in this section is open.**

---

## 10. Current exact gate commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
./scripts/verify.sh
```

The repository-level `scripts/verify.sh` runs these plus the dependency graph
and forbidden-unsafe scan.

---

## 11. Honest wording for reports

Allowed:

> “Shipped compiler and runtime crates enforce the full Level 1–5 lint matrix
> with zero unsafe and zero external dependencies. The build-time CLI is a
> documented Tier C exception for safe filesystem/process access. Test-only panic
> idioms are explicitly scoped. Tool gates not yet executed are listed as open.”

Not allowed:

> “The entire project passes the full standard” while Level 2 is waived in the
> CLI, test exemptions exist, or Kani/Miri/fuzzing/coverage have not run.
