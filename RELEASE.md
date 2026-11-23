# Sirus 1.1.0-safe — Release Notes

**Release type:** safe-tier production prototype
**Tag:** `v1.1.0-safe`
**Platform:** Linux x86-64 end-to-end; PE32+ structural backend
**Dependency policy:** zero external crates in shipped code
**Unsafe policy:** `forbid(unsafe_code)` in every shipped crate and generated VM

---

## 1. What this release guarantees

- A real Linux x86-64 ELF can be protected, executed, and behaviorally verified.
- Protected function bodies are removed.
- The original function jumps into a generated freestanding VM.
- The VM is safe Rust, `no_std`, allocation-free, and self-contained.
- Payload bytes are encrypted; tamper changes execution silently.
- Multiple functions share one VM and one payload.
- The generated VM imports no libc symbols and occupies a non-writable RX
  segment.
- Isolated marker mode and symbol-name/substring mode both work.
- PE32+ images can be parsed and get a valid executable `.sirus` section.
- Full verification, proof, fuzz, red-team, and documentation assets ship in the
  repository.

---

## 2. Included features

### Protector

- ELF64 parser/editor/injector with relocated PHDR table.
- PE32+ parser/editor with section append and checksum regeneration.
- Exact symbol, unique substring, and marker selectors.
- x86-64 subset decoder and lifter with eager flags.
- Bounded fixed-capacity IR and expression arena.
- CFG flattening with random 64-bit state ids.
- Linear MBA expansion, a variable-shift non-linear layer, data-dependent
  modular multiplication with a Newton modular inverse, and constant blinding.
- Opaque guard/decoy synthesis.
- Randomized ISA: four aliases per semantic, per-alias operand order, two
  register maps, per-alias endianness.
- Rolling encrypted manifest/bodies with payload integrity binding.
- Freestanding Rust source generation and `rustc` link.
- Blob validator rejecting relocations, libc symbols, writable segments, or
  inconsistent symbols.
- Function patch (`E9 rel32`, `endbr64` preserved) and random body scrub.
- Atomic output replacement with permission preservation.
- `inspect` for ELF and PE.
- Per-build code/data layout perturbation.

### Verification

- 146 tests (unit + integration + end-to-end), plus opt-in MBA-corpus and
  statistical-timing measurement hooks.
- Real victim compilation and execution differential matrix.
- Differential two-seed builds.
- Tamper and forced-return bypass tests.
- Live memory-dump diagnostic.
- In-tree deterministic fuzzing and libFuzzer harness.
- Kani bounded proofs.
- Miri suite.
- Valgrind, gdb/gcore, readelf/objdump, cargo-show-asm.
- cargo-audit, cargo-deny, cargo-nextest, cargo-tarpaulin, cargo-llvm-cov.
- Ghidra 12.2, radare2 5.9.8, GAMBA, SiMBA, MBA-Blast.
- angr 10.0.7 and KLEE 3.3 bounded symbolic probes.
- Creusot/Why3 boundary proofs.
- Official dudect-bencher timing measurement.

---

## 3. Verified commands

```sh
./scripts/verify.sh
```

Passes formatting, Clippy (`-D warnings`, all targets), 146 tests, rustdoc,
audit, deny, Kani, red-team, and memory-dump diagnostic.

```sh
./scripts/prove.sh
```

Runs Kani, Miri, and libFuzzer. Full Miri execution is slow; set
`SIRUS_FULL_MIRI=1` for the 15-test execution suite. Coverage is enabled with
`SIRUS_COVERAGE=1`.

Recorded evidence:

- Kani: 5 core + 2 VM harnesses.
- Miri: 8 VM lib + 15 VM execution + 75 core tests.
- libFuzzer: 164,729 cumulative executions, no crash.
- Tarpaulin: 88.51% lines (4921/5560).
- llvm-cov: 88.53% lines, 83.97% regions.
- Payload differential: 0.38% equal bytes.
- Full VM segment differential: 10.9% equal bytes.
- Payload entropy: 7.995 Shannon / 7.691 min-entropy bits/byte.
- No obvious strings in `.sirus`.
- Original bodies absent from protected file and live memory.
- Tamper/forced-return alter results; valgrind clean.

---

## 4. Scope boundaries — read before deployment

### Linux ELF

Production-supported. Target function must fit the documented x86-64 subset and
System V integer ABI. Calls, host pointers, SSE/AVX, x87, RIP-relative data,
indirect jumps, and stack arguments are rejected.

### PE / Windows

Container support only. A Win64 VM ABI, Windows linker flow, CFG/guard-table
integration, exception metadata, and Windows loader tests are not included. Do
not deploy PE output as protected Windows software.

### Anti-debug, self-checksum, timing, LFENCE

Not implemented and not claimable under `forbid(unsafe_code)`. They require raw
memory reads, RDTSC, debug-register/context access, OS APIs, or inline assembly.
Payload integrity, encryption, fuel bounds, and structural obfuscation are the
safe-tier substitutes.

### Live memory

The original body and decrypted body cache are absent. VM virtual registers are
memory-resident by design; a live dump can observe transient values, including a
constant used repeatedly. This is documented as a residual.

### External security tools

Ghidra 12.2 and radare2 5.9.8 decompiler smoke tests were executed: patched host
functions reduce to jump stubs / `halt_baddata`, and `.sirus` yields only VM
machinery. GAMBA, SiMBA, and MBA-Blast ran against the exact rewrite corpus;
GAMBA timed out on modular-inverse forms, while SiMBA still reduced them. angr
and KLEE both hit bounded symbolic timeouts with no memory errors. Creusot proved
three boundary contracts. Official dudect-bencher measured the cipher below the
leak threshold and the VM branch far above it. IDA Pro/Hex-Rays and Binary Ninja
require commercial licenses. Ferrocene requires customer authentication. AORAI is
a C-only Frama-C plugin and is not applicable to Rust. Triton had no compatible
prebuilt binding.

### Coverage

The supplied standard requests 100%. This release remains below that target at
**88.51% tarpaulin lines / 88.53% llvm-cov lines**. Defensive/error branches remain uncovered. The proof
script enforces an 85% regression floor; 100% is not claimed.

---

## 5. Upgrade path to a hardened tier

If the zero-unsafe constraint is ever relaxed, a separate audited
`sirus-hardened` boundary can add:

- RDTSC-based timing checks;
- debug-register/context inspection;
- `mlock`/`mprotect`/`madvise` payload controls;
- native-code self-checksum;
- LFENCE/Spectre fences;
- safe host syscall shims.

That tier must remain optional and independently audited; it must not be mixed
into the safe core silently.

---

## 6. Artifact layout

```text
target/release/sirus          stripped protector CLI
crates/                       shipped source
fuzz/                         external fuzzing harness
scripts/verify.sh             fast release gate
scripts/prove.sh              proof/fuzz gate
scripts/red-team.sh           adversarial harness
scripts/memory-dump.sh        live memory diagnostic
scripts/install-tools.sh      tool bootstrap
verification/creusot          Creusot/Why3 boundary proofs
verification/dudect           official dudect-bencher harness
docs/                          architecture, format, threat, proof, traceability
```

---

## 7. Release checklist

| Item | Status |
|---|---|
| Safe Rust / zero unsafe | pass |
| Zero external shipped dependencies | pass |
| Linux ELF end-to-end | pass |
| Multi-function shared VM | pass |
| Randomized ISA/payload | pass |
| Tamper/bypass evidence | pass |
| Kani | pass |
| Miri | pass |
| libFuzzer | pass |
| fmt/clippy/doc/audit/deny | pass |
| 100% coverage | **fail — exact numbers in `docs/VERIFICATION.md`** |
| External decompiler/MBA/symbolic/formal tools | Ghidra/radare2/GAMBA/SiMBA/MBA-Blast/angr/KLEE/Creusot/dudect executed; IDA/BN/Ferrocene/Triton unavailable; AORAI not applicable |
| Windows runtime | **not supported** |
| Anti-debug/self-code/timing/LFENCE | **not possible under safe-Rust constraint** |
| Live memory constant secrecy | **residual** |
| VM constant-time execution | **fail — dudect VM branch max \|t\| = 358.73** |
| Full handler-layout mutation | **partial (10.9% segment equality)** |

This is the final safe-tier product. The items marked fail/open are release
exceptions, not hidden passes.
