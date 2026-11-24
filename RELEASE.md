# Sirus 1.5.0-hardened — Release Notes

**Release type:** safe-tier prototype plus optional hardened tier
**Tag:** `v1.5.0-hardened`
**Platform:** Linux x86-64 end-to-end; Win64 PE32+ runtime verified under Wine in normal, constant-time, and hardened modes; native Windows CI passed
**Dependency policy:** zero external crates in shipped code
**Unsafe policy:** `forbid(unsafe_code)` in the safe tier; the opt-in `sirus-hardened` crate and `--hardened` generated entries allow unsafe code

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
- PE32+ images can be protected and executed under Wine with the Win64 VM runtime
  in normal and `--constant-time` modes.
- Branchy, looping, and private-memory functions can run in fixed-pass oblivious constant-time
  mode; private memory uses an oblivious full-stack scan and longer loops report `LoopBound`.
- Optional `--hardened` entries add Linux `/proc` debugger detection, Windows
  PEB debugger detection, serialized RDTSC timing checks, and LFENCE.
- `sirus harden-check` reports debugger state, TSC delta, and Windows debug
  registers (`unsupported` on Linux user mode).
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
- Fast keyed ARX body stream with SipHash-2-4 retained for manifest, integrity,
  and key derivation.
- Per-invocation alias-spec caching and linear-time register-map inversion.
- Encrypted per-build decode-table image, decrypted once per call.
- Masked virtual registers and private stack memory at rest.
- `max`, `balanced`, and `minimal` profiles.
- Opaque guard/decoy synthesis.
- Oblivious constant-time runner with fixed pass budget, active-frontier masks,
  predicated register writes, and branch/loop support.
- Randomized ISA: four aliases per semantic, per-alias operand order, two
  register maps, per-alias endianness.
- Per-build semantic-handler arm permutation and engine/entry layout preambles in the generated runtime.
- Optional hardened entry checks: raw-syscall Linux tracer detection, PEB
  debugger detection on Windows, RDTSC/LFENCE timing budget, and Windows
  debug-register reporting through `harden-check`.
- Rolling encrypted manifest/bodies with payload integrity binding.
- Freestanding Rust source generation and `rustc` link.
- Blob validator rejecting relocations, libc symbols, writable segments, or
  inconsistent symbols.
- Function patch (`E9 rel32`, `endbr64` preserved) and random body scrub.
- Atomic output replacement with permission preservation.
- `inspect` for ELF and PE.
- Per-build code/data layout perturbation.

### Verification

- 183 tests (unit + integration + end-to-end), plus opt-in MBA-corpus and
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

Passes formatting, Clippy (`-D warnings`, all targets), 183 tests, rustdoc,
audit, deny, Kani, red-team, and memory-dump diagnostic.

```sh
./scripts/prove.sh
```

Runs Kani, Miri, and libFuzzer. Full Miri execution is slow; set
`SIRUS_FULL_MIRI=1` for the 20-test execution suite. Coverage is enabled with
`SIRUS_COVERAGE=1`.

Recorded evidence:

- Kani: 5 core + 4 VM harnesses.
- Miri: 10 VM lib + 20 VM execution (1 ignored under Miri) + 82 core tests.
- libFuzzer VM: 2,929,049 cumulative executions, no crash.
- libFuzzer formats: 17,482,146 PE and 15,055,973 ELF runs, no crash.
- Reproducible output: identical normal, hardened, and constant-time binaries
  for a fixed input and seed.
- Tarpaulin: 86.17% lines (6001/6964).
- llvm-cov: 87.05% lines, 82.74% regions.
- Payload differential: 0.40% equal bytes.
- Handler arms are permuted per build; full VM segment differential remains
  2.21% equal bytes (a metric, not a uniqueness proof).
- Payload entropy: 7.996 Shannon / 7.751 min-entropy bits/byte.
- Per-call benchmark: native ~1.2-1.9 ns; Sirus default ~78.1 us; hardened
  ~78.8 us; constant-time ~209 us; hardened constant-time ~205 us; balanced
  ~57.2 us; minimal ~14.1 us; VMProtect 3.11 demo virtualization ~8.5 us.
- Cold startup: Sirus ~0.6 ms; VMProtect demo ~2.6 s (packed).
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

Wine-tested Win64 runtime for the strict leaf subset (branches and loops
included), normal and constant-time. Native Windows loader/CFG/exception
metadata, signing, imports/TLS, and Windows anti-debug are not implemented. The
Linux ELF path remains the primary production path.

### Anti-debug, self-checksum, timing, LFENCE

Permanently out of scope for the safe tier (ADR-020). They require raw memory
reads, RDTSC, debug-register/context access, OS APIs, or inline assembly. Payload
integrity, encryption, fuel bounds, oblivious execution, and structural
obfuscation are the safe-tier substitutes.

### Live memory

The original body and decrypted body cache are absent. Virtual registers and
private stack bytes are XOR-masked at rest with per-invocation keys; the live
snapshot diagnostic no longer observes the previously exposed constant. A decoded
value can still exist briefly in a local inside one executing instruction.

### External security tools

Ghidra 12.2 and radare2 5.9.8 decompiler smoke tests were executed: patched host
functions reduce to jump stubs / `halt_baddata`, and `.sirus` yields only VM
machinery. GAMBA, SiMBA, and MBA-Blast ran against the exact rewrite corpus;
GAMBA timed out on modular-inverse forms, while SiMBA still reduced them. angr
and KLEE both hit bounded symbolic timeouts with no memory errors. Creusot proved
three boundary contracts. Official dudect-bencher measured the cipher below the
leak threshold, the normal VM branch far above it, and the straight-line,
branchy, and looping `--constant-time` cases below it. Commercial/licence-gated
tools are outside the local gate and are not release blockers.

### Coverage

The agreed prototype target is **above 85%**. This release measures
**86.17% tarpaulin lines / 87.05% llvm-cov lines**. 100% is not claimed, but the
85% floor is met and enforced by the proof script.

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
bench/                        call-overhead benchmark victim
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
| Safe tier / zero unsafe | pass; hardened tier is opt-in unsafe |
| Zero external shipped dependencies | pass |
| Linux ELF end-to-end | pass |
| Multi-function shared VM | pass |
| Randomized ISA/payload | pass |
| Tamper/bypass evidence | pass |
| Kani | pass |
| Miri | pass |
| libFuzzer | pass |
| fmt/clippy/doc/audit/deny | pass |
| Coverage floor 85% | **pass — 86.17% tarpaulin / 87.05% llvm-cov lines** |
| External evidence tooling | Ghidra/radare2/GAMBA/SiMBA/MBA-Blast/angr/KLEE/Creusot/dudect executed; commercial/licence-only tools are outside the local gate |
| Windows runtime | **Wine + native Windows leaf subset (branches/loops), normal + constant-time + hardened** |
| Anti-debug/self-code/timing/LFENCE | **permanently out of scope for the safe tier (ADR-020)** |
| Live memory constant secrecy | masked at rest; snapshot scan passes; instruction-local transient may remain |
| VM constant-time execution | normal profile leaks (dudect max \|t\| = 225); `--constant-time` straight-line/branch/loop/memory cases pass (worst \|t\| = 2.82) |
| Hardened tier | **opt-in `--hardened`; unsafe allowed; anti-debug, RDTSC/LFENCE, Windows debug-register report** |
| Handler-layout mutation | **per-build handler/engine/entry layout preambles; 2.21% segment equality** |

The safe tier remains the default and still forbids unsafe code. The hardened
tier is opt-in and carries an explicit unsafe policy. Native Windows-host CI and
the Wine gate both pass for normal, constant-time, and hardened Win64 output.
