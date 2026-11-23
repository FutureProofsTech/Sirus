# Sirus Threat Model

---

## 1. Assets

- Proprietary integer logic (license checks, key derivation, protocol constants).
- Encryption/decryption keys or salts embedded in protected code.
- Algorithm structure and control flow.
- Build-specific ISA geometry and payload encryption keys.

---

## 2. Adversary capabilities

Assume the adversary can:

- read the complete binary and all metadata;
- run Ghidra, IDA, Binary Ninja, radare2, objdump, custom parsers;
- run MBA simplifiers (GAMBA, SiMBA, MBA-Blast) and symbolic execution
  (angr, KLEE, Triton, Z3);
- trace with Intel PIN, Frida, DynamoRIO, QEMU, gdb;
- dump process memory at any time;
- patch file or memory bytes;
- compare two protected builds;
- fuzz the VM;
- use a hypervisor debugger or hidden hardware breakpoints.

The adversary does **not** have unlimited CPU time in the intended cost model.
Sirus raises cost; it does not prove impossibility.

---

## 3. Security objectives

| ID | Objective | Current control | Evidence |
|---|---|---|---|
| O1 | Remove readable original logic | original body scrubbed, flattened encrypted bytecode | red-team patch/scrub check |
| O2 | Obscure operations | bounded MBA, constant blinding, randomized ISA | MBA property tests, differential builds |
| O3 | Make builds independent | new seed changes opcodes, orders, maps, states, block order, keys, MBA, decoys | payload equality ratio 0.0038 |
| O4 | Detect payload tampering | integrity hash mixed into effective key | tamper test: wrong output, no crash/hang |
| O5 | Keep host safe | no unsafe, checked decode, no heap, gas limit, private memory | fuzz, Miri, Kani, malformed suite |
| O6 | Resist forced-return bypass | protected results are data used by the host; no boolean-only API | forced-return bypass changes output |
| O7 | No leaked VM strings | generated engine uses no formatting/panic strings | static string scan of `.sirus` |

---

## 4. Non-objectives

- Protection against an adversary with unlimited local time and full hardware
  instrumentation.
- Anti-debugging through unsafe OS APIs.
- Hiding the existence of a VM.
- Preventing patch-to-return attacks on callers outside the protected function.
- Formal cryptographic proof of the custom cipher construction.
- Whole-program virtualization.
- Protecting functions requiring calls, host memory, floating point, or
  unsupported instructions.

---

## 5. Attack-cost analysis

| Attack | Cost increase | Residual |
|---|---|---|
| Static disassembly | body is gone; VM is flattened; opcode table encrypted/derived | symbols still identify patched entry; decompiler work remains |
| MBA simplification | layered exact identities, non-linear subexpressions | a powerful solver may reduce shallow expressions |
| Dynamic tracing | encrypted byte-at-a-time decode, per-build state ids, decoy paths | DBI can still record semantics |
| Taint analysis | args influence flags, state selection, and rolling decode geometry | taint depth is not formally proven |
| Symbolic execution | large random states, encrypted manifest, MBA, finite fuel | path explosion is probabilistic, not proven |
| Memory dumping | no decrypted body cache; instructions live in locals only | live dump can observe transient VM register values (including repeated constants) |
| Forced return | host consumes derived data, not only a boolean | caller-side patch remains possible |
| Differential analysis | new seed changes every payload field and much code/data layout | full `.sirus` segment equality measured at 10.9% |
| VM fuzzing | checks and fuel prevent panic/OOB/hang | semantic garbage may still produce a value |

---

## 6. Failure policy

- Build-time failure: typed error, no output file, no partial mutation.
- Runtime malformed payload: deterministic `BadPayload`, value `0`.
- Fuel exhaustion: deterministic `FuelExhausted`, value `0`.
- Trap: explicit `Trap`.
- No unwinding, allocation, or host memory access.

Returning `0` is not a security failure in itself: the host is expected to use
protected data in ways that fail downstream if incorrect.

---

## 7. Known residuals

1. **No native self-code checksum.** Reading arbitrary machine code requires
   unsafe/OS support. Payload and static plan material are integrity-bound, but
   the engine code itself can be patched.
2. **No timing/debug detection.** RDTSC, debug-register inspection, and DBI
   overhead detection require unsafe or OS-specific code. Not implemented and
   not claimed.
3. **No LFENCE/Spectre mitigation.** Safe Rust cannot emit the required barrier.
4. **Handler layout reuse.** Payload/ISA/state geometry mutates per build, but the
   interpreter's semantic skeleton is shared. Full `.sirus` equality is 10.9% in
   the current differential sample.
5. **Coverage and tool gaps.** Coverage remains below the 100% target. Ghidra,
   radare2, GAMBA/SiMBA/MBA-Blast, angr, KLEE, Creusot, and dudect-bencher have
   been run; IDA/Binary Ninja, Ferrocene, and Triton were unavailable, and AORAI
   is not applicable to Rust. The VM's data-dependent branch leaks timing under
   dudect-bencher.
6. **Windows runtime.** PE container support is implemented structurally only.
7. **Symbol metadata.** Protected output retains the host symbol table; the
   injected `.sirus` segment itself contains no obvious strings.
8. **Local attacker.** A process owner can instrument memory/CPU and eventually
   recover behavior.

These residuals are recorded so no report can overstate protection.
