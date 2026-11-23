# Changelog

All notable changes to Sirus.

## [1.0.0-safe] — 2026-11-23

### Added

- Linux x86-64 ELF end-to-end protection.
- PE32+ structural parser/editor and `.sirus` section injection.
- Strict x86-64 subset decoder, IR lifter, eager flag semantics.
- CFG flattening, random state ids, block shuffling.
- Bounded MBA expansion, constant blinding, opaque decoy guards.
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

- Coverage is 87.64% tarpaulin / 89.54% llvm-cov, not 100%.
- Windows runtime execution is not supported.
- Anti-debug, self-code checksum, RDTSC timing, debug-register inspection, and
  LFENCE are not implemented under safe Rust.
- Live VM register state can expose transient values to a process memory dump.
- Full handler-layout mutation is partial.
- Ghidra/IDA/Binary Ninja, GAMBA/SiMBA, angr/KLEE, Creusot, AORAI, Ferrocene, and
  dudect-style timing gates have not been executed.
