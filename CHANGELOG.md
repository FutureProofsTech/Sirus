# Changelog

All notable changes to Sirus.

## [1.5.0-hardened] — 2026-11-24

### Added

- Optional `--hardened` generated-entry mode:
  - Linux debugger detection through `/proc/self/status` using raw syscalls;
  - Windows PEB `BeingDebugged` and `NtGlobalFlag` detection;
  - serialized RDTSC timing checks with a configurable cycle budget;
  - LFENCE before and after timing reads;
  - fail-closed return `0` when a check fails.
- `sirus harden-check` host diagnostic:
  - reports debugger state;
  - reports TSC delta;
  - reports debug registers on Windows;
  - reports debug registers as unsupported on Linux user mode.
- `sirus-hardened` workspace crate (`no_std`, unsafe allowed, no external
  dependencies) used only by the hardened tier.
- PE/Win64 hardened runtime path tested under Wine.

### Changed

- Generated entry thunks now route through `execute_entry`, so `--constant-time`
  actually selects the oblivious runner.
- Per-build engine and entry layout preambles reduce full VM segment equality
  from 11.33% to 2.21%.
- The safe tier remains `forbid(unsafe_code)`; only `sirus-hardened` and
  `--hardened` generated VMs allow unsafe code.

## [1.4.0-safe] — 2026-11-24

### Added

- Constant-time oblivious execution for branchy and looping functions:
  - compiles control flow instead of rejecting branches;
  - executes every block on every fixed pass with predicated register writes;
  - supports a configurable fixed pass budget (`--constant-time-passes`,
    default 256) and reports `LoopBound` when the frontier does not converge;
  - supports private `Load`/`Store` through a fixed full-stack oblivious scan;
  - adds branchy and loop dudect benchmarks alongside the straight-line case;
  - final dudect results: straight-line +2.82059, branch -2.74189, loop
    -1.57791, memory -0.97765 (all below |t| = 5).
- Per-build semantic-handler arm permutation and engine/entry layout preambles in the generated runtime.
- Win64 constant-time runtime check under Wine (branch and loop fixture).
- Staged native Windows CI job and `scripts/windows-native-check.sh`.

### Changed

- `--constant-time` no longer rejects all branches; it uses the oblivious runner.
- Documentation marks native Windows loader/CFG validation as an external
  evidence gap and treats unsafe anti-debug/LFENCE controls as permanently out of
  scope under the safe-Rust constraint.

## [1.3.0-safe] — 2026-11-24

### Added

- `--constant-time` subset mode:
  - rejects data-dependent conditional branches;
  - rejects private `Load`/`Store` operations;
  - disables decoy branches;
  - uses branchless mask-select semantics.
- Constant-time dudect control: branchless VM profile measured
  `max t = -0.87721`; normal branchy profile measured `max t = -225`.
- Masked virtual registers and private stack bytes at rest.
- Encrypted per-build decode-table image.
- `max`, `balanced`, and `minimal` performance profiles.
- Win64 PE32+ runtime injection verified under Wine 11.20; native Windows CI
  workflow staged but not yet run.

### Changed

- Branchless `SEM_SELECT` implementation in the reference VM.
- Common data-dependent select path no longer emits a conditional branch.
- Documentation and traceability distinguish the constant-time subset from the
  normal virtualization profile.

### Known limitations

- The constant-time mode is a **subset**, not a general branchy/looping
  constant-time VM. Branchy and memory-touching functions are rejected.
- The normal virtualization profile remains data-dependent and leaks timing.
- Windows native loader/CFG/exception validation and Windows-host CI are pending;
  the Wine leaf runtime (branches and loops) passes.
- 100% coverage is not claimed; exact coverage is in `docs/VERIFICATION.md`.
## [1.2.0-safe] — 2026-11-24

### Added

- Fast keyed ARX body stream; SipHash-2-4 remains the integrity, manifest, and
  key-derivation primitive.
- Per-invocation alias-spec cache and linear-time register-map inversion.
- Faster deterministic table expander.
- Encrypted per-build decode-table image with per-call decryption.
- Masked virtual registers and private stack memory at rest.
- `max`, `balanced`, and `minimal` profiles.
- Reproducible call-overhead benchmark (`bench/overhead.rs`,
  `scripts/bench-overhead.sh`) with default, balanced, and minimal profiles.
- Measured comparison against VMProtect 3.11 Linux demo virtualization.

### Changed

- Default benchmark per-call overhead reduced from ~539 us to ~74 us on the
  benchmark host; balanced profile ~55 us, minimal ~15 us. VMProtect 3.11 demo
  virtualization of the same function is ~10 us.
- Live memory snapshot no longer observes the sensitive constant; VM state is
  masked at rest.
- Full `.sirus` segment equality is 10.95% between two seeds; payload equality is
  0.40%; entropy is 7.996 Shannon / 7.751 min-entropy.
- Coverage on the final tree: 86.17% tarpaulin lines (6001/6964); llvm-cov 87.05% lines.

### Known limitations

- The body stream is obfuscation, not a cryptographic cipher or MAC.
- VM execution remains non-constant-time; dudect measures a branch timing leak.
- Default profile is about 8x slower per call than VMProtect demo virtualization;
  minimal is about 2x slower but disables MBA/decoy layers.
- Coverage remains below 100%.
- Windows runtime, anti-debug/anti-tamper, native self-checksum, and LFENCE remain
  unsupported or impossible under the safe-Rust constraint.
- IDA/Binary Ninja, Ferrocene, and Triton are unavailable; AORAI is not applicable
  to Rust.

## [1.1.0-safe] — 2026-11-23

### Added

- Non-linear MBA layer: variable-shift bit recombination, data-dependent odd
  multiplication, and a six-step Newton modular inverse.
- Exact post-rewrite MBA corpus generator and external GAMBA/SiMBA/MBA-Blast
  harness.
- Ghidra 12.2 headless and radare2 `pdc` static-analysis checks.
- angr and KLEE bounded symbolic probes.
- Creusot/Why3 boundary proof models under `verification/creusot`.
- Official dudect-bencher harness under `verification/dudect`, plus an in-tree
  Welch timing measurement.
- Expanded end-to-end differential matrix over 20 deterministic random inputs.
- KLEE, Creusot, angr, MBA, and timing gates in the opt-in proof script.

### Changed

- Linear MBA rewrite probability raised to 99% per eligible node.
- The non-linear wrapper is inserted once per function at the first block with
  arithmetic statements, keeping block bodies within bounds.
- Full-build differential improved: `.sirus` equal-byte ratio is now 10.9%
  (previously 25.2%); payload equal-byte ratio is 0.38%.
- Payload entropy: 7.995 Shannon / 7.691 min-entropy.
- Coverage on the final tree: 88.51% tarpaulin lines / 88.53% llvm-cov lines.

### Known limitations

- Miri rerun on the final tree: 75 core, 8 VM lib, and 15 VM execution tests
  passed.
- Coverage remains below the 100% target; the exact final numbers are in
  `docs/VERIFICATION.md`.
- VM execution is not constant-time. Official dudect-bencher measured the
  data-dependent branch at max |t| = 358.73; the cipher path stayed below 5.
- GAMBA times out on the modular-inverse corpus and parser-rejects variable
  shifts; SiMBA still reduces the inverse form.
- angr and KLEE are bounded negative searches, not unsatisfiability proofs.
- Live VM register state can expose transient values to a process memory dump.
- Full handler-layout mutation is partial.
- Windows runtime execution is not supported.
- IDA/Binary Ninja, Ferrocene, and Triton were unavailable; AORAI is C-only and
  not applicable to the Rust product.
- Anti-debug, native self-code checksum, RDTSC timing, debug-register inspection,
  and LFENCE are not implementable under the zero-unsafe constraint.

## [1.0.0-safe] — 2026-11-23

### Added

- Linux x86-64 ELF end-to-end protection.
- PE32+ structural parser/editor and `.sirus` section injection.
- Strict x86-64 subset decoder, IR lifter, eager flag semantics.
- CFG flattening, random state ids, block shuffling.
- Bounded linear MBA expansion, constant blinding, opaque decoy guards.
- Per-build randomized ISA with four aliases per semantic, operand order,
  register maps, and endianness.
- Rolling encrypted manifest/body payload, integrity-key binding, fuel.
- Freestanding `no_std` VM synthesis and `rustc` link pipeline.
- ELF PHDR relocation, RX VM segment, section regeneration, jump patch, scrub.
- Multi-function shared VM and entry thunks.
- CLI: protect, inspect, version, help; marker/symbol/substring selectors.
- Kani proofs, Miri suite, deterministic fuzz, libFuzzer target.
- Red-team harness: scrub, entropy, string leak, differential, tamper, bypass,
  valgrind, live memory diagnostic.
- Full documentation and traceability matrix.

### Known limitations

- Coverage was 87.64% tarpaulin / 89.54% llvm-cov, not 100%.
- Windows runtime execution was not supported.
- Anti-debug, self-code checksum, RDTSC timing, debug-register inspection, and
  LFENCE were not implemented under safe Rust.
- Live VM register state could expose transient values to a process memory dump.
- Full handler-layout mutation was partial.
- Ghidra/IDA/Binary Ninja, GAMBA/SiMBA, angr/KLEE, Creusot, AORAI, Ferrocene, and
  dudect-style timing gates had not been executed.
