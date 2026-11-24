# Sirus 1.3.0-safe — Release Notes

**Release type:** safe-tier production prototype
**Tag:** `v1.3.0-safe`
**Platform:** Linux x86-64 end-to-end; Win64 PE32+ runtime verified under Wine; native Windows CI staged
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
- PE32+ images can be protected and executed under Wine with the Win64 VM runtime.
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

- 167 tests (unit + integration + end-to-end), plus opt-in MBA-corpus and
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

Passes formatting, Clippy (`-D warnings`, all targets), 167 tests, rustdoc,
audit, deny, Kani, red-team, and memory-dump diagnostic.

```sh
./scripts/prove.sh
```

Runs Kani, Miri, and libFuzzer. Full Miri execution is slow; set
`SIRUS_FULL_MIRI=1` for the 15-test execution suite. Coverage is enabled with
`SIRUS_COVERAGE=1`.

Recorded evidence:

- Kani: 5 core + 3 VM harnesses.
- Miri: 9 VM lib + 15 VM execution + 81 core tests.
- libFuzzer: 1,872,687 cumulative executions, no crash.
- Tarpaulin: 86.77% lines (5437/6266).
- llvm-cov: 87.14% lines, 82.78% regions.
- Payload differential: 0.40% equal bytes.
- Full VM segment differential: 11.01% equal bytes.
- Payload entropy: 7.996 Shannon / 7.751 min-entropy bits/byte.
- Per-call benchmark: native 1.45-1.89 ns; Sirus default ~77 us; balanced
  ~58 us; minimal ~16 us; VMProtect 3.11 demo virtualization ~8.5 us.
- Cold startup: Sirus ~0.7 ms; VMProtect demo ~2.6 s (packed).
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

Wine-tested Win64 runtime for the strict leaf subset (branches and loops included). Native Windows
loader/CFG/exception metadata, signing, imports/TLS, and Windows anti-debug are
not implemented. The Linux ELF path remains the primary production path.

### Anti-debug, self-checksum, timing, LFENCE

Not implemented and not claimable under `forbid(unsafe_code)`. They require raw
memory reads, RDTSC, debug-register/context access, OS APIs, or inline assembly.
Payload integrity, encryption, fuel bounds, and structural obfuscation are the
safe-tier substitutes.

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
leak threshold, the normal VM branch far above it, and the explicit
`--constant-time` subset below it. Commercial/licence-gated tools are outside the
local gate and are not release blockers.

### Coverage

The agreed prototype target is **above 85%**. This release measures
**86.77% tarpaulin lines / 87.14% llvm-cov lines**. 100% is not claimed, but the
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
| Coverage floor 85% | **pass — 86.77% tarpaulin / 87.14% llvm-cov lines** |
| External evidence tooling | Ghidra/radare2/GAMBA/SiMBA/MBA-Blast/angr/KLEE/Creusot/dudect executed; commercial/licence-only tools are outside the local gate |
| Windows runtime | **Wine-tested leaf subset (branches/loops)**; native Windows CI staged |
| Anti-debug/self-code/timing/LFENCE | **not possible under safe-Rust constraint** |
| Live memory constant secrecy | masked at rest; snapshot scan passes; instruction-local transient may remain |
| VM constant-time execution | normal profile leaks (dudect max \|t\| = 225); `--constant-time` subset passes (max \|t\| = 0.88) |
| Full handler-layout mutation | **partial (11.01% segment equality)** |

This is the final safe-tier product. The items marked fail/open are release
exceptions, not hidden passes.
