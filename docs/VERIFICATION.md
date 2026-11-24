# Verification Record

**Host:** Linux x86-64, Fedora-class environment
**Stable toolchain:** rustc 1.99.0 (2026-09-28)
**Nightly toolchain:** 2026-08-03 / 2026-08-21 family for Miri and fuzzing
**Kani:** 0.68.0
**Project state:** all features described in `README.md` implemented and tested
**Last evidenced run:** current working tree before final documentation commit

This file records commands actually executed. Anything not executed is listed as
an open gap, not inferred.

---

## 1. Fast gate

```sh
./scripts/verify.sh
```

Result: **exit 0**. The script runs:

- `cargo fmt --all -- --check` — pass
- `cargo clippy --workspace --all-targets -- -D warnings` — pass
- `cargo test --workspace` — pass
- `cargo deny check` — pass
- `cargo audit` — pass
- `cargo kani -p sirus-core` — pass
- `cargo kani -p sirus-vm` — pass
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` — pass
- dependency tree inspection — only path crates
- forbidden unsafe-construct scan — clean
- `./scripts/red-team.sh` — pass

---

## 2. Test inventory

`cargo test --workspace` now runs **158 tests**, all passing; the MBA corpus and
statistical timing tests are `#[ignore]` measurement hooks and are not part of
the normal count.

```text
158 passed, 0 failed
```

Breakdown:

| Target | Tests |
|---|---:|
| `sirus-binfmt` unit tests | 18 |
| `sirus-binfmt` real-loader test | 1 |
| `sirus-core` unit tests | 80 |
| `sirus-protector` unit tests | 21 |
| `sirus-protector` end-to-end | 1 |
| `sirus-protector` pipeline errors | 1 |
| `sirus-protector` marker end-to-end | 1 |
| `sirus-vm` unit tests | 9 |
| `sirus-vm` execution | 15 |
| `sirus-vm` deterministic fuzz | 2 |
| `sirus-vm` malformed payloads | 9 |

The end-to-end tests compile a real victim, protect it, compare outputs, check
body scrubbing, compare two seeds, tamper payload, forced-return bypass, and run
the real protected binary.

### Release profile build

```sh
cargo build --release --workspace
```

Result: exit 0; `target/release/sirus` is a stripped 617 KiB PIE with the
documented release profile. A real victim protected with the release binary
matched native output for the branch/loop sample.

---

## 3. Kani

```sh
cargo kani -p sirus-core
cargo kani -p sirus-vm
```

Results:

- `sirus-core`: **5 / 5 harnesses verified**, 0 failures.
  - `manifest_size_is_total`
  - `bounded_push_is_total`
  - `read_unsigned_is_bounded`
  - `read_signed_is_bounded`
  - `sign_extend_is_total`
- `sirus-vm`: **3 / 3 harnesses verified**, 0 failures.
  - `load_memory_is_bounded`
  - `store_memory_is_bounded`

A full symbolic decoder harness was attempted and rejected as too large for CBMC
on this host. The decoder is instead covered by an opcode/error test corpus and
libFuzzer/Miri. This is recorded as a proof-scope limitation, not a pass.

---

## 4. Miri

Toolchain: `cargo +nightly miri` (miri 0.1.0, 2026-08-03).

Final passes on the current tree:

```text
cargo +nightly miri test -p sirus-vm --lib
  8 tests passed (0.89 s)

cargo +nightly miri test -p sirus-vm --test execution
  15 tests passed (1742.62 s)

cargo +nightly miri test -p sirus-core
  80 tests passed (446.76 s)
```

This includes the slice-based VM memory helpers, stack/push/pop semantics,
branch/loop executions, malformed payloads, the non-linear MBA equivalence
checks, and all core tests. Miri is extremely slow and is not part of the fast
gate.

---

## 5. libFuzzer

```sh
cd fuzz
cargo +nightly fuzz run vm -- -max_total_time=20 -rss_limit_mb=4096 -timeout=5
```

Result:

```text
Done 348151 runs in 21 second(s)
```

The final-tree session completed 348,151 runs with no crash. Across the earlier
101,274-run sessions plus this run, the cumulative total is **887,210
executions**.

No crash, panic, OOB, or timeout. The fuzz target builds a valid integrity key
for arbitrary payloads so the decoder body path is exercised, not only the
integrity rejection path.

In-tree deterministic fuzz additionally runs 20,000 random payloads and 10,000
mutations of a valid payload.

---

## 6. Coverage

```sh
cargo tarpaulin --workspace --all-targets --engine Llvm \
  --out Xml --out Lcov --output-dir target/coverage-all \
  --exclude-files 'target/*' --exclude-files 'bench/*' --timeout 120
```

Result: **90.01% line coverage (5224 / 5804 lines)** with
`--exclude-files 'target/*' --exclude-files 'bench/*'`.

Per file at that run:

```text
sirus-binfmt/src/elf.rs         674/781
sirus-binfmt/src/lib.rs          64/66
sirus-binfmt/src/pe.rs          293/317
sirus-core/src/decode.rs        744/779
sirus-core/src/encode.rs        367/387
sirus-core/src/error.rs          51/52
sirus-core/src/ir.rs            168/189
sirus-core/src/lifter.rs        537/671
sirus-core/src/mba.rs           255/281
sirus-core/src/program.rs       435/462
sirus-core/src/shared/chacha.rs 111/111
sirus-core/src/shared/cipher.rs  67/67
sirus-core/src/shared/derive.rs 314/314
sirus-core/src/shared/format.rs  19/24
sirus-core/src/shared/sip.rs     68/68
sirus-protector/src/cli.rs      162/163
sirus-protector/src/entropy.rs   84/114
sirus-protector/src/error.rs     21/27
sirus-protector/src/main.rs      25/25
sirus-protector/src/pipeline.rs 183/255
sirus-protector/src/vmgen.rs    227/252
sirus-vm/src/engine.rs          355/399
```

The 100% target is **not met**. `scripts/prove.sh` enforces an 85% regression floor with `--fail-under 85`; 100% remains the release target.

Secondary independent measurement with LLVM source-based coverage:

```sh
cargo llvm-cov --workspace --all-targets --summary-only
```

```text
TOTAL regions 85.14% (2732 missed of 18381)
TOTAL functions 81.71% (128 missed of 700)
TOTAL lines 89.97% (996 missed of 9935)
```

The two tools instrument differently; both show the same residual error/I/O
branches. Neither reaches 100%. Uncovered lines are predominantly defensive error
returns, malformed-binary branches, and CLI/pipeline I/O failures. The exact LCOV
report is generated under `target/coverage-all/`.

---

## 7. Red-team harness

```sh
./scripts/red-team.sh
```

Actual output:

```text
PASS patch/scrub sirus_demo_check: changed=43/43
PASS patch/scrub sirus_demo_loop: changed=138/139
PASS payload entropy: shannon=7.996 min=7.751 distinct=256
PASS no obvious strings in injected segment
PASS differential payload: equal-byte ratio=0.0040 sizes=45669/45607
PASS differential VM segment: equal-byte ratio=0.1101 sizes=55120/55008
PASS tamper and bypass observably alter results
PASS valgrind
== radare2 decompiler smoke test ==
PASS radare2 pdc: 2 patched functions show only jump/goto stubs
== live memory-dump diagnostic ==
PASS original protected body absent from live memory
PASS sensitive constant not observed in this snapshot
PASS original body absent from protected file
== red-team gates passed ==
```

Additional measured facts:

- full `.sirus` segment equal-byte ratio between the two seeds: **0.1101**;
- protected binary preserves native output for branch/loop/overflow cases;
- original function bodies are gone after the jump;
- payload tamper yields deterministic wrong output without crash/hang;
- forced-return bypass changes output;
- valgrind reports no runtime memory errors on the protected sample;
- live memory dump: original protected body absent, plaintext `.sirus` body not
  cached, virtual registers/private memory masked at rest, and the sensitive
  constant was not observed (`scripts/memory-dump.sh`).

---

## 8. Dependency and policy gates

```text
cargo audit           -> 0 vulnerabilities, 4 path crate dependencies
cargo deny check      -> advisories ok, bans ok, licenses ok, sources ok
cargo tree            -> only workspace path crates, no external runtime crates
```

`fuzz/` is excluded from the workspace and uses libFuzzer only as external
verification tooling. It is not linked into shipped crates.

---

## 8b. Ghidra and radare2 static analysis

Ghidra 12.2 headless (`scripts/ghidra-check.sh`) examined 7 scoped functions:
5 in `.sirus` and 2 patched host targets. It completed 7/7 decompilations.
The patched host targets ended in `halt_baddata()` after the jump/scrub; the VM
segment yielded only engine/state functions. Despite the decompiler's output,
the host binary as a whole retains Rust/std strings; scoped `.sirus` string scans
remain clean.

radare2 5.9.8 `pdc` (`scripts/radare2-check.sh`) produced only:

```c
goto loc_0x57004; // or loc_0x570ae
return rax;
```

for the two patched functions, no original logic.

The generated Ghidra output is in `target/ghidra/sirus-decompiled.txt`; radare2
output in `target/radare2/pdc.txt`.

## 7b. Call overhead and VMProtect comparison

```sh
SIRUS_BENCH_PROFILE=default  ./scripts/bench-overhead.sh
SIRUS_BENCH_PROFILE=balanced ./scripts/bench-overhead.sh
SIRUS_BENCH_PROFILE=minimal  ./scripts/bench-overhead.sh
```

Measured on the same `bench/overhead.rs` function and host (median of 9
protected samples; VMProtect demo 3.11 virtualization measured separately):

| Build | Per call | Relative to native | Relative to VMProtect |
|---|---:|---:|---:|
| Native | ~2.1 ns | 1x | ~0.0002x |
| VMProtect 3.11 demo, virtualization | ~10.0 us | ~4,800x | 1x |
| Sirus default | ~74 us | ~37,000x | ~7.4x |
| Sirus balanced (`depth=1, budget=128, decoys=1`) | ~55 us | ~26,000x | ~5.5x |
| Sirus minimal (`depth=0, budget=0, decoys=0`) | ~15 us | ~7,500x | ~1.5x |

Sirus append size is about 30 KiB (0.6% of the benchmark binary); VMProtect demo
packs the 4.4 MiB input to a 1.17 MiB output but pays a multi-second startup cost
on this host. The benchmark explicitly compares the same virtualized leaf
function, but VMProtect's anti-debug/packing/demo checks and Sirus's MBA/decoy
levels are not equivalent security profiles. Full discussion and feature matrix:
`docs/POSITIONING.md`.

The optimization path was: fast keyed ARX body stream, cached per-invocation
alias table, faster table PRNG, and linear register-map inversion. Before these
changes the default profile measured about 539 us/call.

## 8c. External MBA simplification

```sh
./scripts/mba-check.sh
```

The script asks a test-only hook in `sirus-core` to emit the exact expressions
after the production MBA pass, then runs external simplifiers. GAMBA (`96691c0`),
SiMBA (`2281799`), and MBA-Blast (`ceb12c2`) were cloned under
`/opt/sirus-tools`; these are verification tools, not shipped dependencies.

Result (30 actual expressions):

```text
SiMBA linear baseline: 18/18 verified reductions
GAMBA linear baseline: 18/18 verified reductions
GAMBA inverse-only nonlinear corpus: 6/6 timeouts/tool failures
GAMBA variable-shift nonlinear corpus: 6/6 parser failures
SiMBA inverse-only corpus: 6/6 equivalence-verified reductions
MBA-Blast: 3/9 verified; 6 parser/tool failures on its grammar subset
```

Interpretation:

- the linear MBA forms are fully reduced by both general and linear tools;
- the modular-inverse form is not reduced by GAMBA inside the 20 s cap;
- GAMBA rejects the variable-shift form at parse time;
- SiMBA still reduces the inverse form; it is a linear simplifier and this is
  not a nonlinear resistance claim;
- MBA-Blast handled 3 of the 9 shift-free linear cases it accepted and rejected
  the rest with parser failures.

Exact output: `target/mba/summary.txt`; corpus: `target/mba/corpus.tsv`.

## 8d. angr symbolic probe

```sh
/opt/sirus-tools/venv-angr/bin/python scripts/angr-check.py
```

angr 10.0.7 loaded the real protected ELF and started at the patched
`sirus_demo_check` symbol with two symbolic 64-bit arguments. The requested
target was the reference output for `(7, 3)`:
`11936045730314344032`.

```text
PASS symbolic timeout: active=1 deadended=0 errored=0 elapsed=120.00s
```

This is a bounded timeout, not a proof of unsatisfiability. It shows that the
symbolic engine did not find a preimage within 120 seconds. Unicorn support was
unavailable in the Python 3.13 environment, so angr used its VEX engine.

## 8e. KLEE symbolic VM

```sh
./scripts/klee-check.sh
```

KLEE 3.3 (LLVM 18) runs in the official `klee/klee` container. The generated
freestanding VM source is compiled to LLVM bitcode with rustc 1.78 (the matching
LLVM 18 vintage). For compiler compatibility only, `const fn` is changed to
`fn`; the executed bodies are otherwise the generated source.

```text
KLEE: done: total instructions = 2180488
KLEE: done: completed paths = 0
KLEE: done: partially completed paths = 2
KLEE: done: generated tests = 1
PASS KLEE symbolic run (no memory errors in explored paths)
```

The symbolic arguments did not complete a path within 60 seconds. This is
again a bounded resistance result, not a proof.

## 8f. Creusot proofs

```sh
./scripts/creusot-check.sh
```

Creusot/Why3 discharged three contracts in `verification/creusot`:

```text
Proved (3 files) ✔
```

The models are the exact arithmetic guards used by the runtime:

- `end_in_bounds` returns true exactly when `start + width <= length`;
- every successful `checked_access` satisfies `address + width <= memory.len()`;
- `manifest_size(count)` is `Some(count * 16 + 8)` for every accepted count.

`creusot-std` is tooling-only and is kept out of the shipped workspace. This is
model-level proof of the boundary logic, not a proof of the entire interpreter.

## 8g. Dudect timing measurement

Official `dudect-bencher` 0.7.0:

```sh
./scripts/dudect-external.sh
```

```text
bench crypto      ... : n == +0.200M, max t = +3.37690
bench crypto_same ... : n == +0.199M, max t = -1.01007
bench vm          ... : n == +0.029M, max t = -745.81435
```

The cipher path stays below the usual |t| = 5 leak threshold. The deliberately
data-dependent VM branch path is far above it, so the VM is **not** measured as
constant-time. This confirms the residual: safe-Rust virtualization hides logic,
not execution timing.

The in-tree Welch harness (`scripts/dudect-check.sh`) independently measured
`crypto_t=-3.794` and `vm_t=-56.685` over 120,000 samples. Both measurements
agree on the direction; neither is a proof of constant time.

## 8h. Tools not executed or not applicable

| Tool | Status |
|---|---|
| IDA Pro / Hex-Rays | commercial licence unavailable; not run |
| Binary Ninja | commercial licence unavailable; not run |
| Ferrocene | requires customer-portal authentication; prebuilt archives were not accessible |
| AORAI | installed as Frama-C 33.0, but it verifies C call automata; Sirus emits Rust/ELF/PE and has no C intermediate to verify. Investigated, not applicable without a separately validated C extraction |
| Triton | no compatible prebuilt DBI binding was available; angr and KLEE provide the symbolic evidence instead |
| BinDiff / Diaphora | binary metrics are measured in-tree; no BinDiff/Diaphora run |

---

## 9. Assembly inspection

`cargo-show-asm 0.2.65` is installed. Assembly was inspected with it and with
`objdump`/`readelf` during VM development. The blob validator additionally
rejects undefined symbols, relocations, and writable load segments, which catches
libc/PLT contamination before injection.

Example:

```sh
cargo asm -p sirus-core --lib finish
cargo asm -p sirus-core --lib 1
```

---

## 10. Open gaps

| Gap | Status |
|---|---|
| 100% line/branch coverage | open; measured 90.01% tarpaulin / 89.97% llvm-cov on the final tree |
| IDA / Binary Ninja headless validation | commercial licences unavailable |
| Ghidra/radare2 | executed with scoped evidence |
| GAMBA / SiMBA / MBA-Blast | executed; linear forms reduce, GAMBA times out on modular-inverse forms, variable shifts parser-fail |
| angr symbolic probe | executed; 120 s timeout, no preimage |
| KLEE symbolic VM | executed; 60 s timeout, no completed path, no memory errors |
| Creusot | executed; 3 boundary models proved |
| AORAI | installed (Frama-C 33.0) but C-only; not applicable to the Rust product |
| Ferrocene | customer authentication unavailable |
| dudect-bencher | executed; cipher below \|t\|=5, VM branch far above it |
| Triton | no compatible prebuilt binding; not run |
| live process memory dump scan | pass; masked VM state, constant not observed |
| Windows PE runtime execution | not supported |
| handler-layout full mutation | partial; `.sirus` equality 11.01% |
| native self-code checksum / debug detection / LFENCE | impossible under safe-Rust-only |

These are not silently waived. They are release blockers for any claim of full
compliance with the supplied red-team/code-standard documents.
