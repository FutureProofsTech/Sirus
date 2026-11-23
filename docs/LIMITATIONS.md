# Sirus Limitations and Deliberate Deviations

---

## 1. Virtualized code restrictions

Sirus supports a strict subset of x86-64. Any unsupported instruction fails the
build. It does not silently skip or best-effort translate.

### Supported

Common integer operations on registers and the private stack, including `mov`,
`movzx`, `movsx`, `movsxd`, `lea`, `add`, `sub`, `and`, `or`, `xor`, `cmp`,
`test`, `inc`, `dec`, `neg`, `not`, `imul`, shifts, rotates, `push`, `pop`,
`leave`, `cdqe`, `jmp`, `jcc`, `ret`, `cmovcc`, `setcc`, and 8/16/32/64-bit
memory widths.

### Rejected

- calls and indirect calls/jumps;
- RIP-relative data and absolute memory;
- jump tables and computed jump targets;
- SSE/AVX, x87, MMX, floating point;
- syscalls, `rdtsc`, `cpuid`, privileged or IO instructions;
- atomics and fences;
- segment overrides, address-size override, lock prefix;
- VEX/EVEX encodings;
- host pointer dereferences;
- 7th and later stack arguments;
- cross-block flag liveness that cannot be proven;
- functions larger than 16 KiB or programs exceeding fixed capacities.

A typical Rust function that calls `libcore` helpers, panics, invokes an
allocator, formats text, or touches `std` is not directly virtualizable. Mark
compact leaf logic instead.

---

## 2. ABI limits

- Working backend: System V AMD64 (Linux).
- Up to six integer arguments.
- One integer result.
- No floating-point arguments/results.
- No stack arguments.
- Protected code cannot call external functions.
- The VM uses a private 4 KiB byte stack; functions with deeper frames or larger
  locals can fail or halt.

The VM return value is `0` on any fail-closed condition. Host code must consume
protected results as data so a wrong value causes a downstream failure.

---

## 3. Safe-Rust conflict resolutions

| Requested control | Why safe Rust cannot implement it | Alternative |
|---|---|---|
| Self machine-code checksum | requires raw memory reads | encrypted payload integrity + derived-key binding |
| RDTSC timing detection | unsafe intrinsic | fuel bound only |
| Debug register inspection | unsafe OS/context API | not implemented |
| DBI/hypervisor detection | unsafe timing/OS introspection | structural encryption and polymorphism |
| LFENCE / Spectre fences | inline asm or unsafe intrinsic | not implemented |
| Windows anti-debug APIs | unsafe FFI | not implemented |

No hidden unsafe path exists. The project chooses safe Rust over fake completion
of these controls.

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

- PE32+ AMD64 parsing and `.sirus` section injection are implemented.
- A Win64 VM blob, Windows ABI thunk generation, loader validation, CFG/guard
  table integration, and exception metadata are **not** implemented.
- Do not claim Windows runtime protection.

---

## 5. Security residuals

- Full `.sirus` segment differential equality is 25.2% between two seeds; handler
  code skeleton is reused. Payload equality is 0.36%.
- No formal proof that MBA expressions resist GAMBA/SiMBA/angr.
- No whole decrypted bytecode is cached, and the static injected segment has no
  obvious strings. However, the live-memory diagnostic shows that a sensitive
  constant used repeatedly can be observed transiently in VM register state.
  Virtual registers are memory-resident in the safe-Rust VM; this is inherent,
  not hidden.
- Payload integrity is not a MAC against an attacker who can rewrite both
  expected hash and key shares; it detects accidental/naive patching, not an
  unlimited local adversary.
- Tampering can produce deterministic wrong outputs rather than a visible crash;
  this is intentional deep binding behavior.
- The project is not a substitute for formal audit, hardware security, or
  anti-cheat kernel design.

---

## 6. Verification gaps

- Measured line coverage with all targets: **87.64%**, not 100%. The proof script enforces an 85% regression floor; 100% remains a release target.
- Kani proofs cover bounded primitives and memory bounds; the full decoder is too
  large for CBMC and is covered by tests/fuzzing instead.
- Miri covers core and VM unit/execution suites; it is very slow.
- Ghidra/IDA/Binary Ninja headless analysis, GAMBA/SiMBA, angr/KLEE, Creusot,
  AORAI, Ferrocene, and dudect-style timing analysis have not been run.
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
