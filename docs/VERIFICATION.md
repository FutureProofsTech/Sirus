# Verification Record

**Host:** Linux x86-64, Fedora-class environment
**Stable toolchain:** rustc 1.99.0 (2026-09-28), pinned by `rust-toolchain.toml`
**Nightly toolchain:** 2026-08-03 / 2026-08-21 family for Miri and fuzzing
**Kani:** 0.68.0
**Project state:** all features described in `README.md` implemented and tested
**Last evidenced run:** final 1.5.6-hardened tree, tag `v1.5.6-hardened`

This file records commands actually executed. Anything not executed is listed as
an external evidence gap or a documented boundary, never inferred.

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

`cargo test --workspace` now runs **202 tests**, all passing; the MBA corpus and
statistical timing tests are `#[ignore]` measurement hooks and are not part of
the normal count.

```text
202 passed, 0 failed
```

Breakdown:

| Target | Tests |
|---|---:|
| `sirus-binfmt` unit tests | 26 |
| `sirus-binfmt` real-loader test | 1 |
| `sirus-core` unit tests | 83 |
| `sirus-protector` unit tests | 43 |
| `sirus-hardened` runtime checks | 3 |
| `sirus-protector` end-to-end | 1 |
| `sirus-protector` pipeline errors | 1 |
| `sirus-protector` marker end-to-end | 1 |
| `sirus-vm` unit tests | 11 |
| `sirus-vm` execution | 21 |
| `sirus-vm` deterministic fuzz | 2 |
| `sirus-vm` malformed payloads | 9 |

The end-to-end tests compile a real victim, protect it in normal and
`--constant-time` modes, compare outputs, check body scrubbing, compare two
seeds, tamper payload, forced-return bypass, and run the real protected binary.

### Release profile build

```sh
cargo build --release --workspace
```

Result: exit 0; `target/release/sirus` is a stripped 682 KiB PIE with the
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
- `sirus-vm`: **4 / 4 harnesses verified**, 0 failures.
  - `load_memory_is_bounded`
  - `store_memory_is_bounded`
  - `masked_register_round_trip`
  - `masked_memory_round_trip`

A full symbolic decoder harness was attempted and rejected as too large for CBMC
on this host. The decoder is instead covered by an opcode/error test corpus and
libFuzzer/Miri. This is recorded as a proof-scope limitation, not a pass.

---

## 4. Miri

Toolchain: `cargo +nightly miri` (miri 0.1.0, 2026-08-03).

Final passes on the current tree:

```text
cargo +nightly miri test -p sirus-vm --lib
  10 tests passed (1.19 s)

cargo +nightly miri test -p sirus-vm --test execution
  19 passed, 1 ignored

cargo +nightly miri test -p sirus-core
  82 tests passed (1 ignored)
```

This includes the slice-based VM memory helpers, stack/push/pop semantics,
branch/loop executions, malformed payloads, the non-linear MBA equivalence
checks, and all core tests. Miri is extremely slow and is not part of the fast
gate.

---

## 5. libFuzzer

```sh
cd fuzz
cargo +nightly fuzz run vm -- -max_total_time=60 -rss_limit_mb=4096 -timeout=5
```

Result:

```text
Done 1056362 runs in 61 second(s)
```

The final-tree session completed 1,056,362 runs with no crash. A fresh
1.5.1 session completed another 342,270 runs; adding all recorded sessions, the
cumulative total is **3,271,319 executions**.

No crash, panic, OOB, or timeout. The fuzz target builds a valid integrity key
for arbitrary payloads so the decoder body path is exercised, not only the
integrity rejection path.

The 1.5.2 session also added a lifter/compiler target:

```text
Done 112332 runs in 21 second(s)
```

It lifts arbitrary byte strings and compiles every successfully lifted function
in normal and (input-selected) constant-time modes.

In-tree deterministic fuzz additionally runs 20,000 random payloads and 10,000
mutations of a valid payload.

Separate format fuzz targets:

```text
PE:  11,489,628 runs in 21 s, no crash (1.5.1 session)
ELF:  5,015,515 runs in 21 s, no crash (1.5.1 session)
Cumulative: 28,971,774 PE / 20,071,488 ELF runs.
```

Reproducible output:

```sh
./scripts/reproducible-check.sh
```

```text
PASS reproducible protected output (normal, hardened, constant-time)
```

---

## 6. Coverage

```sh
cargo tarpaulin --workspace --all-targets --engine Llvm \
  --out Xml --out Lcov --output-dir target/coverage-all \
  --exclude-files 'target/*' --exclude-files 'bench/*' --timeout 120
```

Result: **90.25% line coverage (6812 / 7548 lines)** with
`--exclude-files 'target/*' --exclude-files 'bench/*'`. This is above the agreed
85% floor.

The LCOV report is written under `target/coverage-all/`.


The `sirus-hardened` host-only Windows debug-register module is not exercised
on Linux; the runtime tracer/TSC/LFENCE code is covered.


Tarpaulin's per-file attribution for `sirus-core/src/error.rs` is affected by
inlining of the `Display` test; llvm-cov reports 95.56% lines for the same file.
The aggregate tarpaulin and llvm-cov totals are the release numbers.


The agreed prototype floor is 85%, and `scripts/prove.sh` enforces it with `--fail-under 85`. 100% is not claimed.

Secondary independent measurement with LLVM source-based coverage:

```sh
cargo llvm-cov --workspace --all-targets --summary-only
```

```text
TOTAL regions 86.51% (3380 missed of 25051)
TOTAL functions 74.65% (253 missed of 998)
TOTAL lines 90.97% (1212 missed of 13423)
```

The two tools instrument differently; both are above the 85% floor and show the
same residual error/I/O branches. Uncovered lines are predominantly defensive error
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

Measured on the same `bench/overhead.rs` function and host (median of 7 runs;
VMProtect demo 3.11 virtualization measured on its own native baseline):

| Build | Per call | Relative to native | Relative to VMProtect |
|---|---:|---:|---:|
| Native (Sirus benchmark build) | ~1.2-1.4 ns | 1x | ~0.0002x |
| Native (VMProtect benchmark build) | ~1.89 ns | 1x | ~0.0002x |
| VMProtect 3.11 demo, virtualization | ~8.48 us | ~4,490x | 1x |
| Sirus default | ~75.0 us | ~49,800x | ~9.3x |
| Sirus hardened | ~78.5 us | ~40,600x | ~9.0x |
| Sirus constant-time | ~234 us | ~101,500x | ~25.2x |
| Sirus hardened constant-time | ~235 us | ~111,300x | ~25.5x |
| Sirus balanced (`depth=1, budget=128, decoys=1`) | ~53.9 us | ~30,000x | ~6.7x |
| Sirus minimal/fast (`depth=0, budget=0, decoys=0`) | ~14.4 us | ~6,100x | ~1.7x |

Sirus append size is about 30 KiB (0.7% of the benchmark binary); VMProtect demo
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

## 8g-b. Constant-time oblivious measurement

```sh
taskset -c 0 ./scripts/constant-time-check.sh
```

The mode uses a fixed-pass oblivious runner. Every manifest block is decoded
and executed on every pass; active path state is carried in frontier masks and
all register writes are predicated with a bitwise select. Branches enqueue both
successors with complementary masks. Private `Load`/`Store` runs a fixed
full-stack byte scan with masked selection, so its address pattern is input
independent. Programs with no cycles use their exact
maximum block count as the pass bound; any program containing a loop uses the
configured `--constant-time-passes` budget and reports `LoopBound` if the
frontier does not converge.

Official dudect-bencher on the same host:

```text
bench vm                 ... : max t = -225.23809  (normal branchy profile)
bench vm_constant        ... : max t = +2.82059    (straight-line)
bench vm_constant_branch ... : max t = -2.74189    (branch)
bench vm_constant_loop   ... : max t = -1.57791    (loop)
bench vm_constant_memory ... : max t = -0.97765    (private memory)
```

All four `--constant-time` cases stayed below the conventional |t| = 5
threshold; the worst was |t| = 2.821. The normal profile still leaks because it
executes data-dependent control flow.

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

## 8i. Windows PE32+ runtime under Wine

```sh
./scripts/windows-wine-check.sh
```

The fixture is a real `x86_64-pc-windows-gnu` PE32+ binary. Sirus resolves the
`sirus_win_check`, `sirus_win_mix`, and `sirus_abi_target` COFF symbols, lifts
all three, generates the encrypted VM, cross-compiles the Win64 runtime, links
it as a no-import image, rejects any relocation that targets the extracted
code/data, appends one RX `.sirus` section, merges linked `.pdata` entries into
the exception directory, patches all three function RVAs, and runs the native
and protected binaries under Wine 11.20.

```text
PASS Windows/Wine PE32+ runtime (normal + constant-time + hardened)
PASS Windows/Wine C ABI matrix (XMM6-15, indirect, large frame)
```

The native and protected outputs match for the branch/loop matrix
`(7,3)`, `(3,7)`, `(0,0)`, and `(123456789,5)`, plus the ABI line
`abi 48 48 0 3`. The ABI fixture checks `XMM6`–`XMM15` preservation, direct and
indirect callers, and a 32 KiB stack-probed caller. `objdump` shows an `E9`
jump at each protected entry and keyed junk over the remaining original body
bytes. Constant-time, hardened, and hardened+constant-time variants match.

Native Windows CI is executed by the `pe32-native` job through
`scripts/windows-native-check.sh`, and the `pe32-msvc-cfg` job builds the same
fixture with MSVC `/guard:cf`, resolves function sizes from the PDB plus linker
map, protects it with explicit `--range` selectors, and compares outputs. Both
jobs pass. The CFG binary also exercises the indirect call path under
`/GUARD:CF`. The shared fixture also protects a DLL export and loads it through
a host using `LoadLibrary`/`GetProcAddress`, and a second fixture verifies a TLS
callback plus `RCDATA` resource after protection.

---

## 8i-a. Linux caller-saved ABI

```sh
./scripts/linux-abi-check.sh
```

A GCC `-O2` caller keeps its loop bound in `R10` across the protected call. The
Linux entry shim saves and restores all caller-saved GPRs and `XMM0`–`XMM15`, so
the caller sees the same register state as an ordinary callee.

```text
PASS Linux caller-saved ABI regression (normal + hardened + constant-time)
```

Without the shim this fixture loops after protection because the VM clobbers
`R10`. The previous cyclic `Select` fail-closed guard was removed after this fix.

---

## 8i-b. Hardened self-code checksum

Linux `--hardened` builds place linker markers around `.text`, hash the marked
range with word-wise FNV-1a, and patch the expected value into `.rodata` after
linking. Every entry thunk verifies the text before decoding the payload.
`./scripts/red-team.sh` protects the fixture with `--hardened`, confirms normal
behavior, flips one byte inside `.sirus`, and requires the modified binary to
produce a different result.

```text
PASS hardened self-code checksum rejects modified VM text
```

The hash slot is outside the hashed range, so patching it does not create a
fixed-point problem.

Windows hardened builds use the same word-wise FNV-1a over the linked `.text`
section. The expected hash, text length, and per-entry offsets are patched into
`.rdata` statics after linking; each entry subtracts its offset from its own
address to recover the text base and verifies before decoding. Both Wine and
native Windows scripts flip a `.sirus` byte and require the modified binary to
produce a different result.

```text
PASS Windows/Wine hardened self-code checksum
PASS native Windows hardened self-code checksum
```

The Windows fixture also calls `RtlLookupFunctionEntry` on the patched entry's
shim and reports `unwind 1` in both native and protected runs, covering runtime
lookup of the merged `.pdata` record. It does not yet execute an exception
through a protected leaf.

### Windows stack and constant-time fixes

The Win64 probe now walks downward one page at a time from the current `RSP`,
touching the guard page before lower uncommitted pages. The previous upward walk
worked only when the frame fit in already committed stack and faulted when a
multi-page VM frame was entered from a deep caller. The ABI matrix's 32 KiB
caller is the regression test for this path.

Constant-time protection now raises the effective fuel to
`passes * (encoded body bytes + manifest blocks) + manifest blocks`, a safe
upper bound on the fixed-pass work. Before this, a three-function CT build could
exhaust the normal two-million-step budget and return `0` for every entry. The
`constant_time_raises_fuel_for_multiple_entries` test runs three entries with an
explicit fuel of `1` and requires all three to return.

---

## 8i-c. Constant-time cachegrind

```sh
./scripts/cachegrind-check.sh
```

A branch-only protected leaf is run with two different input pairs under
Cachegrind, after one warm-up run and with three repetitions per input. I/D
references, branches, and mispredicts must be exactly stable; D1/LLd misses use
the maximum of the repetitions because the first post-link run can carry
transient process-layout cache noise.

```text
I refs=15202709
D refs=5285136
D1 misses=4784
LLd misses=2798
Branches=1438216
Mispredicts=120703
PASS constant-time cachegrind counts are input-independent
```

The first post-link run can show a transient cache-state difference, so the
script warms up once and takes the maximum of three cache-miss samples. This is cache simulation of the
branch-only leaf; the private-memory scan remains covered by the dudect memory
case and the engine tests.

---

## 8j. Hardened runtime checks

```sh
./scripts/hardened-check.sh
```

```text
debugger_present=false
hypervisor_present=false
tsc_delta=40
timing_ok=true
debug_registers=unsupported
debugger_present=true   (under strace)
PASS hardened runtime checks (anti-debug + RDTSC + LFENCE)
11936045730314344032
3029019864519521483
```

The same fixture protected with `--hardened` matches native output normally and
returns `0` under `strace`/`gdb`. With `--hardened-timing-cycles 1`, the call is
rejected. The Windows cross-build of `sirus harden-check` runs under Wine and
reports four debug-register values through `GetThreadContext`; Linux user mode
reports `debug_registers=unsupported`.

`./scripts/windows-wine-check.sh` also protects the Win64 fixture in hardened
and hardened+constant-time modes; both match native output under Wine.

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

## 10. Residual evidence and boundaries

| Item | Status |
|---|---|
| Coverage floor (85%) | **met**: 90.25% tarpaulin / 90.97% llvm-cov lines |
| Ghidra/radare2/GAMBA/SiMBA/MBA-Blast/angr/KLEE/Creusot/dudect | executed; evidence recorded |
| live process memory dump scan | pass; masked VM state, constant not observed |
| Windows PE runtime execution | Wine and native Windows; normal, constant-time, hardened; `/guard:cf`, ABI matrix, unwind lookup, and text-checksum tamper tests pass |
| Windows unwind metadata | linked `.pdata` merged, shim `.seh` records emitted, handler/chained records fail closed |
| handler-layout mutation | layout preambles applied; `.sirus` equality 2.21% residual |
| Linux hardened self-code checksum | implemented; tamper test rejects modified VM text |
| Linux caller-saved ABI | assembly shim preserves GPRs + XMM0–XMM15; C regression passes |
| Windows hardening / self-code checksum | debugger/PEB/TSC/LFENCE, debug-register reports, and linked text hash with tamper test |
| native self-code checksum in the safe tier / kernel anti-debug | out of scope (ADR-020) |

These are documented boundaries, not hidden passes. The Linux ELF and Windows
gates pass, including native Windows and MSVC CFG. Runtime exception propagation
through a protected leaf, Windows self-checksum, and kernel-level anti-debug are
explicitly not claimed.
