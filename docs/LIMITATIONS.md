# Sirus Limitations and Deliberate Deviations

---

## 1. Virtualized code restrictions

Sirus supports a strict subset of x86-64. Any unsupported instruction fails the
build. It does not silently skip or best-effort translate.

### Supported

Common integer operations on registers and the private stack, including `mov`,
`movzx`, `movsx`, `movsxd`, `lea`, `add`, `sub`, `and`, `or`, `xor`, `cmp`,
`test`, `inc`, `dec`, `neg`, `not`, `imul`, shifts, rotates, `push`, `pop`,
`leave`, `cdqe`, `bswap`, `jmp`, `jcc`, `ret`, `cmovcc`, `setcc`, and
8/16/32/64-bit memory widths.

Also supported:

- RIP-relative reads of read-only data (the referenced bytes are copied into
  private VM memory at build time);
- direct `call rel32` between functions selected in the same protection run,
  with a bounded guest call stack;
- SSE2 `movdqu`/`movdqa`, `pxor`/`pand`/`por`, `paddq`/`psubq`,
  `paddd`/`psubd`, `pmuludq`, `punpcklqdq`/`punpckhqdq`,
  `psrldq`/`pslldq`, and `movq`/`movd` forms;
- VEX-encoded 128-bit AVX versions of the same integer operations, including
  `vpsrldq`/`vpslldq` and `vmovq`; 256-bit AVX remains rejected;
- `rep movsb`/`movsq` and `rep stosb`/`stosq` on the private memory region;
- `bswap` 32/64-bit in normal and constant-time modes; the undefined 16-bit
  form with a `0x66` operand-size prefix is rejected rather than guessed;
- `--follow-calls` automatically lifts direct local callees that resolve to a
  real function symbol; external or unresolved calls fail closed;
- System V stack arguments 7 through 12 and Win64 stack arguments 5 through 10.

### Rejected

- external calls, indirect calls, and indirect jumps;
- calls to a function outside the selected protection set;
- writable RIP-relative globals and absolute memory;
- jump tables and computed jump targets;
- 256-bit AVX/AVX2, x87, MMX, floating point;
- syscalls, `rdtsc`, `cpuid`, privileged or IO instructions;
- atomics and fences;
- segment overrides, address-size override, lock prefix;
- VEX encodings outside the documented 128-bit integer subset and all EVEX
  encodings;
- host pointer dereferences;
- more than 12 System V arguments or more than 10 Win64 arguments;
- cross-block flag liveness that cannot be proven;
- functions larger than 16 KiB or programs exceeding fixed capacities.

A typical Rust function that calls `libcore` helpers, panics, invokes an
allocator, formats text, or touches `std` is not directly virtualizable. Mark
compact leaf logic instead.

---

## 2. ABI limits

- Working backends: System V AMD64 (Linux) and Win64 (PE32+).
- Up to six integer register arguments plus up to six stack arguments on
  System V; up to four register arguments plus up to six stack arguments on
  Win64.
- One integer result.
- No floating-point arguments/results.
- Protected code can call another function selected in the same protection run.
  Calls to external functions fail closed.
- The VM uses a private 4 KiB byte stack and up to 2 KiB of read-only data;
  functions with deeper frames or larger locals can fail or halt.

The VM return value is `0` on any fail-closed condition. Host code must consume
protected results as data so a wrong value causes a downstream failure.

---

## 3. Safe-Rust conflict resolutions

| Requested control | Why safe Rust cannot implement it | Alternative |
|---|---|---|
| Self machine-code checksum | requires raw memory reads | Linux hardened tier: linker-marked text hash checked on every entry; safe/default tier: payload integrity + derived-key binding |
| RDTSC timing detection | unsafe intrinsic | safe tier: fuel bound; hardened tier: RDTSC budget |
| Debug register inspection | unsafe OS/context API | hardened tier: Windows `GetThreadContext`; Linux user mode unsupported |
| DBI/hypervisor detection | unsafe timing/OS introspection | structural encryption and polymorphism |
| LFENCE / Spectre fences | inline asm or unsafe intrinsic | hardened tier: LFENCE; no formal Spectre proof |
| Windows anti-debug APIs | unsafe FFI | hardened tier: PEB checks; no kernel32 API imports |

No hidden unsafe path exists in the default safe tier. The optional
`sirus-hardened` crate and `--hardened` generated entries contain explicit unsafe
code and are not mixed into the default runtime. Both Linux and Windows hardened builds now verify a linked text hash on every entry; hypervisor and debug-register reporting are available in the hardened tier.

---

## 4. Platform limitations

### Linux ELF

- ELF64 x86-64 only.
- Executable must be `ET_EXEC` or `ET_DYN`.
- Extended ELF numbering (0xffff counts / `SHN_XINDEX`) is rejected.
- Injection requires enough header space after minor relocations and fails
  cleanly otherwise.
- Function symbols come from `.symtab` or `.dynsym`; fully stripped binaries need
  marker mode.
- Markers are raw byte patterns; users must place them so the lifted range is
  valid machine code.
- Host symbol tables are retained; output is not automatically stripped.

### Windows PE

- PE32+ AMD64 parsing, COFF symbol lookup, encrypted VM section injection,
  Win64 thunk generation, checksum updates, RVA patching, and default body
  scrubbing are implemented.
- The leaf subset with branches and loops is verified under Wine 11.20 via
  `scripts/windows-wine-check.sh`.
- Linux entries are wrapped by an assembly shim that preserves all caller-saved
  GPRs and `XMM0`–`XMM15`, matching the Windows shim's IPA-safe behavior.
- Windows loader/CFG execution, guard-page-safe stack probing, linked unwind
  metadata, an ABI matrix, hardened text checksum, DLL exports, TLS callbacks,
  and resources are covered by native CI. Signing, runtime exception
  propagation, and kernel-level anti-debug remain out of scope.
- Native Windows CI passed as the `pe32-native` job and
  `scripts/windows-native-check.sh`; Wine and native Windows both execute the
  normal/constant-time/hardened fixture.

---

## 5. Security residuals

- Full `.sirus` segment differential equality is 2.21% between two seeds; handler
  code skeleton is reused. Payload equality is 0.38%.
- The linear MBA forms are reduced by GAMBA/SiMBA. On the non-linear
  modular-inverse corpus, GAMBA times out at 20 s and the variable-shift form
  parser-fails; SiMBA still reduces the inverse form. This is measured cost
  asymmetry, not a proof of MBA irreducibility.
- The body stream is a keyed ARX obfuscation stream, not a cryptographic cipher.
  SipHash-2-4 remains the manifest/integrity/key primitive.
- `--constant-time` provides oblivious branch/loop/memory execution with a fixed pass
  budget (`--constant-time-passes`, default 256). Every block is executed on
  every pass, the active frontier is carried in masks, and register writes are
  predicated. Branches and loops converge within the configured bound; longer
  loops return `LoopBound`. Private `Load`/`Store` uses a full-stack byte scan
  with masked selection, making the access pattern fixed but slow. The normal
  branchy profile remains data-dependent and leaks timing.
- Per-call overhead is about 75.0 us for the default profile, 78.5 us for the
  hardened profile, 234 us for the constant-time profile, 235 us for hardened
  constant-time, 53.9 us for the balanced profile, and 14.5 us for the fast/minimal
  profile on the benchmark host. The same function under VMProtect 3.11 demo
  virtualization is about 8.5 us. Sirus has much lower startup cost because it
  does not pack the host image.
- No whole decrypted bytecode is cached, and the static injected segment has no
  obvious strings.
- Virtual registers and private stack bytes are XOR-masked at rest with
  per-invocation keys. The live-memory diagnostic no longer observes the
  previously exposed constant. A decoded value can still exist briefly in a
  local while one instruction executes; an instruction-level tracer is a
  stronger attacker than the snapshot diagnostic.
- Payload integrity is not a MAC against an attacker who can rewrite both
  expected hash and key shares; it detects accidental/naive patching, not an
  unlimited local adversary.
- Tampering can produce deterministic wrong outputs rather than a visible crash;
  this is intentional deep binding behavior.
- The project is not a substitute for formal audit, hardware security, or
  anti-cheat kernel design.

---

## 6. Verification gaps

- The agreed prototype floor is 85% line coverage. The current measured coverage
  is 85.05% tarpaulin / 86.14% llvm-cov and the proof script enforces the 85%
  regression floor. 100% is not claimed.
- Kani proofs cover bounded primitives and memory bounds; the full decoder is too
  large for CBMC and is covered by tests/fuzzing instead.
- Miri covers core units plus 10 VM library and 20 VM execution tests (1 ignored under Miri); it is very slow.
- Ghidra/radare2, GAMBA/SiMBA/MBA-Blast, angr, KLEE, Creusot, and dudect-bencher
  were executed locally; results are in `docs/VERIFICATION.md`.
- IDA/Binary Ninja, Ferrocene, and Triton are commercial/licence/auth-gated and
  are outside the local release gate. AORAI is a C-only Frama-C plugin and is not
  applicable to the Rust product.
- The official dudect-bencher run is complete; the normal VM branch is a measured
  timing leak, while the straight-line, branchy, and looping `--constant-time`
  cases pass the |t| = 5 threshold.
- cargo-show-asm was installed after the main build evidence; assembly inspection
  currently uses objdump/readelf scripts.

All open items are tracked in `docs/VERIFICATION.md`.

---

## 7. What “production prototype” means here

- The full Linux pipeline is real and executed end-to-end.
- Safety gates, fuzzing, Miri, Kani, differential builds, tamper and bypass tests
  pass locally.
- The remaining gaps are explicitly security research/tooling gaps, not hidden
  demo shortcuts.
- A release to untrusted third parties should require external review, Windows
  validation if needed, and a formal cryptographic review of the custom payload
  scheme.
