# Changelog

All notable changes to Sirus.

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
