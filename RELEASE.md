# Sirus 1.5.9-hardened — Release Notes

**Release type:** safe-tier prototype plus optional hardened tier
**Tag:** `v1.5.9-hardened`
**Platform:** Linux x86-64 end-to-end; Win64 PE32+ runtime verified under Wine in normal, constant-time, and hardened modes; native Windows CI passed all three jobs
**Dependency policy:** zero external crates in shipped code
**License:** GPL-3.0-only
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
- PE32+ images can be protected and executed under Wine and native Windows with
  the Win64 VM runtime in normal, `--constant-time`, and `--hardened` modes.
- MSVC `/guard:cf` binaries with PDB/map targeting run protected under native
  Windows, including indirect callers.
- XMM6–XMM15 preservation, indirect callers, and a 32 KiB stack-probed caller
  are covered by the Win64 ABI matrix.
- Windows DLL exports are protected and loaded through a host
  `LoadLibrary`/`GetProcAddress` test.
- Windows TLS callbacks and `RCDATA` resources survive protection.
- Linux caller-saved registers and `XMM0`–`XMM15` are preserved across protected
  calls; an optimized C caller regression is executed.
- Branchy, looping, and private-memory functions can run in fixed-pass oblivious constant-time
  mode; private memory uses an oblivious full-stack scan and longer loops report `LoopBound`.
- RIP-relative reads of read-only data are resolved into a private data blob and
  execute in normal and constant-time modes.
- System V stack arguments 7-12 and Win64 stack arguments 5-10 execute through
  the ABI shims.
- A practical SSE2 integer subset executes: `movdqu`/`movdqa`, bitwise ops,
  32/64-bit add/subtract, `pmuludq`, unpack, byte shifts, and `movq`/`movd`.
- Direct `call rel32` between functions selected in the same protection run
  executes on a bounded guest call stack. External calls and constant-time
  calls fail closed.
- `--follow-calls` auto-lifts direct local callees found by reachable call
  scanning; unresolved and external calls fail closed.
- VEX-encoded 128-bit AVX integer forms execute for the documented operation
  set; 256-bit AVX is rejected.
- `rep movsb`/`movsq` and `rep stosb`/`stosq` execute on private memory in
  normal mode and fail closed in constant-time mode.
- `bswap` 32/64-bit executes in normal and constant-time modes; the undefined
  16-bit form (`66 0F C8+rd`) is rejected because real CPUs disagree on it.
- A SIGALRM handler re-enters the protected function during execution; the
  interrupted and reentrant calls both return the native result.
- The Linux entry shim saves `RBP`, aligns the VM call stack defensively, and
  is exercised by an eight-thread pthread fixture that previously segfaulted on
  a misaligned caller stack.
- Optional `--hardened` entries add Linux `/proc` debugger detection, Windows
  PEB debugger detection, serialized RDTSC timing checks, LFENCE, and a
  self-code checksum over linked VM text on Linux and Windows.
- `sirus harden-check` reports debugger state, TSC delta, and Windows debug
  registers (`unsupported` on Linux user mode).
- Full verification, proof, fuzz, red-team, and documentation assets ship in the
  repository.

---

## 2. Included features

### Protector

- ELF64 parser/editor/injector with relocated PHDR table.
- PE32+ parser/editor with section append and checksum regeneration.
- Exact symbol, unique substring, marker, and explicit RVA:size selectors.
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
  debugger detection on Windows, RDTSC/LFENCE timing budget, Windows
  debug-register reporting through `harden-check`, and linked text checksums on
  both platforms.
- Windows x64 unwind metadata for the injected VM and ABI shims, merged into
  the target exception directory; handler/chained records fail closed.
- Constant-time fuel bound derived from the fixed-pass worst case.
- Rolling encrypted manifest/bodies with payload integrity binding.
- Freestanding Rust source generation and `rustc` link.
- Blob validator rejecting relocations, libc symbols, writable segments, or
  inconsistent symbols.
- Function patch (`E9 rel32`, `endbr64` preserved) and random body scrub.
- Atomic output replacement with permission preservation.
- `inspect` for ELF and PE.
- Per-build code/data layout perturbation.
- A 52-page technical white paper in `docs/whitepaper/` with LaTeX source
  and compiled PDF.

### Security and correctness fixes in 1.5.9

- The Linux entry shim now saves `RBP`, aligns the VM call stack defensively,
  and restores from a frame pointer. A real pthread fixture previously crashed
  with `SIGSEGV` when the caller's stack was not ABI-aligned; the fixture now
  matches native output across eight concurrent workers.
- Constant-time execution now uses a safe address for inactive-block loads and
  suppresses inactive-block stores. A loop that read a stack argument after
  exiting previously returned `BadPayload`; the fixed runner returns the native
  value in the regression test.
- `SEM_BSWAP` is imported into the generated engine dispatch; the missing import
  made the match arm a catch-all in release builds and broke otherwise unrelated
  protected functions. A `bswap` C fixture passes in normal and constant-time
  modes.
- `sirus-protector/build.rs` tracks the embedded VM source fragments. Release
  binaries can no longer silently keep an older engine/wire format after an
  included source file changes.
- The maximum payload is 128 KiB, enough for six max-profile functions while
  staying within test-thread stacks; the previous 64 KiB cap rejected the
  six-function max-profile differential build.
- The `sirus-vm` `trace` feature is an explicit opt-in diagnostic; the default
  build has a no-op sink and no stderr dependency in generated code.

### Verification

- 226 tests (unit + integration + end-to-end), plus opt-in MBA-corpus and
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

Passes formatting, Clippy (`-D warnings`, all targets), 226 tests, rustdoc,
audit, deny, Kani, red-team, and memory-dump diagnostic.

```sh
./scripts/prove.sh
```

Runs Kani, Miri, and libFuzzer. Full Miri execution is slow; set
`SIRUS_FULL_MIRI=1` for the 20-test execution suite. Coverage is enabled with
`SIRUS_COVERAGE=1`.

Recorded evidence:

- Kani: 5 core + 4 VM harnesses.
- Miri: 11/11 VM library tests passed on the 1.5.9 tree; the full execution and core suites are opt-in and slow.
- libFuzzer VM: 4,883,875 cumulative executions, no crash.
- libFuzzer lifter/compiler: 405,768 cumulative runs, no crash.
- libFuzzer formats: 55,510,941 PE and 33,588,394 ELF cumulative runs, no crash.
- Reproducible output: identical normal, hardened, and constant-time binaries
  for a fixed input and seed.
- Release artifacts: `scripts/release-artifacts.sh` emits a binary copy,
  deterministic source archive, SHA-256 manifest, CycloneDX SBOM, and optional
  GPG signature when `SIRUS_SIGNING_KEY` is set.
- `rust-toolchain.toml` pins stable Rust 1.99.0 and the Windows GNU target.
- Tarpaulin: 87.07% lines (7607/8737).
- llvm-cov: 88.25% lines, 84.09% regions, 73.53% functions.
- Payload differential: 0.40% equal bytes.
- Handler arms are permuted per build; full VM segment differential remains
  2.43% equal bytes (a metric, not a uniqueness proof).
- Payload entropy: 7.996 Shannon / 7.751 min-entropy bits/byte.
- Per-call benchmark: native ~1.2-1.9 ns; Sirus default ~75.0 us; hardened
  ~78.5 us; constant-time ~234 us; hardened constant-time ~235 us; balanced
  ~53.9 us; fast/minimal ~14.5 us; VMProtect 3.11 demo virtualization ~8.5 us.
- Cold startup: Sirus ~0.6 ms; VMProtect demo ~2.6 s (packed).
- Constant-time Cachegrind: two inputs produce identical I/D refs, D1/LLd
  misses, branches, and mispredicts for the branch-only protected leaf.
- Dudect: the two-key cipher bench is black-boxed to prevent compiler
  code-path specialization; controlled run cipher |t| = 2.39, constant-time
  subset worst |t| = 3.19, normal branchy VM |t| = 204.
- Linux caller-saved ABI regression: an optimized C caller relying on `R10`
  matches native after protection in normal, hardened, and constant-time modes.
- No obvious strings in `.sirus`.
- Original bodies absent from protected file and live memory.
- Tamper/forced-return alter results; valgrind clean.

---

## 4. Scope boundaries — read before deployment

### Linux ELF

Production-supported. Target function must fit the documented x86-64 subset and
System V integer ABI. RIP-relative reads of read-only data, stack arguments
7-12, the documented SSE2 subset, and direct calls to other selected protected
functions are supported. External calls, host pointers, AVX/x87, writable
RIP-relative globals, indirect jumps, and jump tables are rejected.

### PE / Windows

Wine-tested and native Windows-tested Win64 runtime for the strict leaf subset
(branches and loops included), normal, constant-time, and hardened. Stack
arguments 5-10, RIP-relative read-only data, the documented SSE2 subset, and
direct calls between selected protected functions are supported. Linked unwind
metadata is injected; a `/guard:cf` fixture, ABI matrix, stack-argument
fixture, and direct-call fixture pass. Runtime exception propagation, arbitrary
external calls, signing, imports/TLS edge cases, and kernel anti-debug remain
out of scope. The Linux ELF path remains the primary production path.

### Anti-debug, self-checksum, timing, LFENCE

The default safe tier keeps ADR-020: no unsafe controls. The opt-in
`--hardened` tier adds Linux `/proc` tracer detection, Windows PEB checks,
RDTSC/LFENCE budgets, debug-register reporting, and a linked text checksum on
Linux and Windows. Kernel-level anti-debug and runtime exception propagation
through a protected leaf remain unimplemented.
Payload integrity, encryption, fuel bounds, oblivious execution, and structural
obfuscation remain the default substitutes.

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

### Linux caller-saved ABI

The Linux entry shim saves and restores all caller-saved GPRs and `XMM0`–`XMM15`
around the injected VM. This fixes a caller/IPA assumption where an optimized C
caller kept its loop bound in `R10`; the VM previously clobbered it and the
caller looped. `scripts/linux-abi-check.sh` covers normal, hardened, and
constant-time modes.

### Coverage

The agreed prototype target is **above 85%**. This release measures
**87.07% tarpaulin lines / 88.25% llvm-cov lines**. 100% is not claimed, but the
85% floor is met and enforced by the proof script.

---

## 5. Hardened tier status

The opt-in `sirus-hardened` boundary now ships:

- Linux `/proc` tracer detection and Windows PEB checks;
- debug-register reporting on Windows;
- RDTSC/LFENCE timing budgets;
- a Linux self-code checksum with a tamper test.

Still open for a future hardened line:

- kernel-level anti-debug/DBI detection;
- `mlock`/`mprotect`/`madvise` payload controls;
- a formal Spectre/cache proof.

The tier remains optional and is not mixed into the safe core.

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
scripts/release-artifacts.sh  release binary, checksums, SBOM, optional signature
scripts/cachegrind-check.sh   constant-time cachegrind gate
scripts/linux-abi-check.sh    Linux caller-saved ABI regression
verification/creusot          Creusot/Why3 boundary proofs
verification/dudect           official dudect-bencher harness
docs/                          architecture, format, threat, proof, traceability, white paper
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
| Coverage floor 85% | **pass — 87.07% tarpaulin / 88.25% llvm-cov lines** |
| External evidence tooling | Ghidra/radare2/GAMBA/SiMBA/MBA-Blast/angr/KLEE/Creusot/dudect executed; commercial/licence-only tools are outside the local gate |
| Windows runtime | **Wine + native Windows leaf subset (branches/loops), normal + constant-time + hardened; MSVC `/guard:cf` and ABI matrix pass** |
| Windows unwind metadata | **linked `.pdata` merged; `.seh` shim records; `RtlLookupFunctionEntry` runtime probe; handlers/chained fail closed** |
| Anti-debug/self-code/timing/LFENCE | **safe tier out of scope (ADR-020); opt-in hardened tier adds them, including Linux and Windows text checksums** |
| Live memory constant secrecy | masked at rest; snapshot scan passes; instruction-local transient may remain |
| VM constant-time execution | normal profile leaks (dudect max \|t\| = 204); `--constant-time` straight-line/branch/loop/memory cases pass (worst \|t\| = 3.19) |
| Hardened tier | **opt-in `--hardened`; unsafe allowed; anti-debug, RDTSC/LFENCE, Windows debug-register report, Linux/Windows self-code checksum** |
| Handler-layout mutation | **per-build handler/engine/entry layout preambles; 2.43% segment equality** |

The safe tier remains the default and still forbids unsafe code. The hardened
tier is opt-in and carries an explicit unsafe policy. Native Windows-host CI and
the Wine gate both pass for normal, constant-time, and hardened Win64 output.
