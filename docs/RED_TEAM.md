# Sirus Red-Team Report and Checklist

Run the live harness:

```sh
./scripts/red-team.sh
```

Artifacts are placed under `target/redteam/`.

---

## 1. Static lifting and automated decompilation

**Attack:** Ghidra, IDA, Binary Ninja, radare2, objdump on protected sections.

**Implemented controls:**

- original protected function body overwritten with random bytes;
- no recoverable control-flow graph in native code;
- flattened state machine with random 64-bit state ids;
- no native switch/jump table in the injected VM;
- randomized opcode aliases/operand orders/register maps;
- encrypted manifest and rolling-encrypted bodies;
- no obvious strings in `.sirus`.

**Local evidence:**

```text
PASS patch/scrub sirus_demo_check: changed=43/43
PASS patch/scrub sirus_demo_loop: changed=138/139
PASS no obvious strings in injected segment
```

**Not run:** headless Ghidra / IDA / Binary Ninja comparisons (tools not
installed). Static decompiler resistance is therefore not independently certified.

---

## 2. Automated MBA simplification

**Attack:** GAMBA, SiMBA, MBA-Blast, Triton algebraic/truth-table reduction.

**Implemented controls:** bounded random MBA depth, exact wrapping identities,
nested rewrites, constant shares, non-trivial transitions.

**Local evidence:** MBA equivalence test suite over boundary and seeded random
values; `every_rewrite_preserves_semantics` passes. Generated expressions are
differential-tested through the VM.

**Not run:** GAMBA/SiMBA. A sufficiently strong solver may reduce shallow
expressions. This is a documented residual.

---

## 3. Dynamic binary instrumentation / tracing

**Attack:** PIN, Frida, DynamoRIO, QEMU trace, then dead-code elimination and
handler frequency analysis.

**Implemented controls:** per-build geometry, encrypted byte-at-a-time decode,
decoy state paths, large state space, data-dependent state transition arithmetic.

**Not implemented:** DBI/hypervisor timing detection. Impossible under the
safe-Rust/no-unsafe constraint. A tracer can still record semantics.

**Evidence:** native-vs-VM outputs and differential builds; no automated DBI run.

---

## 4. Dynamic taint analysis

**Attack:** taint user input through VM state to isolate checks.

**Implemented controls:** arguments feed flag computations, condition values,
state selection, and rolling decode interactions; protected results are data
consumed by the host; no simple boolean-only API in the sample.

**Evidence:** forced-return bypass test changes behavior.

**Residual:** no formal taint-explosion proof; a taint engine can still track
operator semantics.

---

## 5. Symbolic execution

**Attack:** angr/KLEE/Triton/Z3 solve a success path.

**Implemented controls:** random large state ids, encrypted manifest lookup,
MBA, decoys, finite fuel, data-dependent transitions.

**Not run:** angr/KLEE. No SMT-solver claim is made.

**Evidence:** local state-space and malformed-payload corpus; fuzzing.

---

## 6. Live memory dumping

**Attack:** dump process memory and inspect decrypted bytecode.

**Implemented controls:**

- manifest/body cipher streams are decrypted in locals;
- no entire decrypted body is stored;
- ISA tables are derived on demand;
- static `.sirus` has no obvious plaintext strings.

**Local evidence:** payload entropy `shannon=7.990`, `min=7.589`, 256 distinct
bytes; static string scan passes.

**Live snapshot evidence:** `scripts/memory-dump.sh` attaches to a long-running
protected VM, dumps process memory, and checks for the original native body and a
unique secret constant.

```text
PASS original protected body absent from live memory
RESIDUAL sensitive constant observed in transient VM register state
PASS original body absent from protected file
```

The constant is used every loop iteration; a safe-Rust VM stores its virtual
registers in memory, so repeated use makes a transient snapshot observable. The
bytecode itself is not cached in decrypted form. This remains a residual, not a
claim of zero plaintext data in live memory.

---

## 7. Byte patching / forced execution

**Attack:** patch the protected function to return true/zero or NOP the VM call.

**Implemented controls:** deep data binding; no boolean-only protected entry in
the harness; payload integrity binding; scrubbed original code.

**Local evidence:**

- payload tamper changes output, does not crash or hang;
- forced-return bypass at the function entry changes output;
- valgrind reports no runtime memory errors.

```text
PASS tamper and bypass observably alter results
PASS valgrind
```

**Residual:** caller-level bypass outside the protected function is outside the
VM's control unless the integration also binds call sites.

---

## 8. Hypervisor and kernel-level debugging

**Attack:** KVM/HyperDbg, spoofed RDTSC, hardware breakpoints.

**Implemented controls:** none that are honest under safe Rust.

**Status:** documented non-capability. Not claimed. No anti-debug API, timing
drift, debug-register inspection, or LFENCE mitigation exists.

---

## 9. Differential binary analysis

**Attack:** BinDiff/Diaphora on two builds.

**Implemented controls:** new seed changes opcode assignment, operand orders,
register maps, endianness, state ids, block order, encryption keys, entry shares,
MBA shapes, decoys, payload size, and code/data offsets.

**Local evidence:**

```text
differential .sirus.payload equal-byte ratio = 0.0036
differential .sirus segment equal-byte ratio = 0.2517
payload sizes = 16555 / 15344 bytes
```

**Residual:** the interpreter skeleton is reused; 25.2% of the full VM segment
matches byte-for-byte at equal offsets. Full handler-layout mutation is not
complete. BinDiff has not been run.

---

## 10. Adversarial VM fuzzing

**Attack:** AFL++/libFuzzer on mutated/truncated/corrupted bytecode.

**Implemented controls:** checked manifest/body ranges, checked registers,
masked shifts, no division, checked memory, deterministic fuel, no panic path.

**Local evidence:**

- deterministic in-tree fuzz: 20,000 random payloads + 10,000 valid-payload
  mutations, no panic/hang;
- libFuzzer: **66,962 runs in 21 s**, no crash;
- Kani: 5 core + 2 VM bounds harnesses verified;
- Miri: core and VM unit/full execution suites pass;
- malformed-payload suite covers bad count/offset/length/opcode/register/trap/fuel.

---

## Summary

| # | Gate | Status |
|---:|---|---|
| 1 | static body removal / no plaintext | pass locally; decompiler tools not run |
| 2 | MBA equivalence | pass locally; GAMBA/SiMBA not run |
| 3 | DBI resistance | partial; detection impossible/unsafe |
| 4 | taint resistance | design + bypass evidence; no formal tool |
| 5 | symbolic resistance | design; angr not run |
| 6 | memory dump | entropy/string pass; live dump scan open |
| 7 | patch/forced return | pass |
| 8 | hypervisor | not capable; documented |
| 9 | differential | payload near-zero; full segment 25.2% residual |
| 10 | fuzzing | pass across in-tree, libFuzzer, Kani, Miri |

No gate in this report is marked “passed” unless its local command was executed.
Open tools and residuals are listed in `docs/VERIFICATION.md` and
`docs/LIMITATIONS.md`.
