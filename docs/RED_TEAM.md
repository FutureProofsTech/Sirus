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

**Executed:**

- **Ghidra 12.2 headless** decompiled 7 scoped functions (5 inside `.sirus`).
  The patched host functions resolve to `halt_baddata()` because of the jump plus
  random scrub; no original branch structure is recovered. The `.sirus` VM
  functions decompile only as engine/state machinery.
- **radare2 5.9.8 `pdc`** reconstructs both patched host functions as only
  `goto VM_entry; return;` with no branch logic.

**Not available:** IDA Pro/Hex-Rays and Binary Ninja require commercial licenses
and are not installed. They remain unexecuted.

---

## 2. Automated MBA simplification

**Attack:** GAMBA, SiMBA, MBA-Blast, Triton algebraic/truth-table reduction.

**Implemented controls:** bounded randomized linear MBA, plus a non-linear
layer that combines variable shifts, data-dependent modular multiplication, and
a six-step Newton modular inverse. The inverse cancels the odd multiplier
exactly for all 64-bit inputs. The wrapper is applied to one arithmetic statement
per function; linear rewrites are applied throughout the CFG.

**Local evidence:** MBA equivalence tests include fixed boundary values and
10,000 deterministic random pairs; `every_rewrite_preserves_semantics`,
`nonlinear_wrap_preserves_semantics_and_uses_hard_operations`, and the expanded
end-to-end input matrix pass.

**Executed:** `scripts/mba-check.sh` generates the exact post-rewrite corpus and
feeds it to the external tools.

```text
SiMBA linear baseline: 18/18 verified reductions
GAMBA linear baseline: 18/18 verified reductions
GAMBA inverse-only nonlinear corpus: 6/6 timeouts/tool failures (20 s cap)
GAMBA variable-shift nonlinear corpus: 6/6 parser failures
SiMBA inverse-only corpus: 6/6 reductions (linear-only tool; not a nonlinear claim)
MBA-Blast: 3/9 verified; 6 parser/tool failures on its grammar subset
```

GAMBA does not reduce the modular-inverse forms within 20 seconds. SiMBA reduces
those exact forms; it is a linear-MBA simplifier and may reason unsoundly outside
its input class, so that result is not a nonlinear-strength claim. The variable
shift form is rejected by GAMBA's parser. These are real cost-asymmetry
measurements, not a proof of irreducibility.

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

**Executed:**

- **angr 10.0.7** on `target/redteam/protected-a`, with symbolic 64-bit inputs
  and a target output taken from the native invocation. The bounded probe timed
  out after **120 s** with one active state, no completed return, and no preimage
  (`scripts/angr-check.py`).
- **KLEE 3.3 (LLVM 18)** on the generated `no_std` VM source, with symbolic
  arguments. The 60 s run executed **2,180,488 instructions**, completed 0 paths,
  left 2 partially completed paths, and reported no memory errors
  (`scripts/klee-check.sh`). The source was compiled with rustc 1.78 for LLVM 18;
  `const fn` was removed only for compiler compatibility.

**Residual:** both runs are bounded searches. A timeout is evidence of cost, not
a mathematical proof that no input exists. No SMT-solver proof is claimed.

**Evidence:** local state-space and malformed-payload corpus; fuzzing.

---

## 6. Live memory dumping

**Attack:** dump process memory and inspect decrypted bytecode.

**Implemented controls:**

- manifest/body cipher streams are decrypted in locals;
- no entire decrypted body is stored;
- ISA tables are derived once per invocation and indexed;
- static `.sirus` has no obvious plaintext strings.

**Local evidence:** payload entropy `shannon=7.996`, `min=7.751`, 256 distinct
bytes; static string scan passes.

**Live snapshot evidence:** `scripts/memory-dump.sh` attaches to a long-running
protected VM, dumps process memory, and checks for the original native body and a
unique secret constant.

```text
PASS original protected body absent from live memory
PASS sensitive constant not observed in this snapshot
PASS original body absent from protected file
```

Virtual registers and private stack bytes are stored XOR-masked with
per-invocation keys; a passive dump no longer exposes the previously observed
constant. A single instruction may hold a decoded local transiently during its
own execution, but the VM state is masked at rest.

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

## 7b. Statistical timing analysis

**Attack:** dudect-style timing classification of a protected branch versus the
cipher path.

**Executed:** official `dudect-bencher` 0.7.0 (`scripts/dudect-external.sh`):

```text
bench crypto      ... : max t = +2.39025
bench crypto_same ... : max t = -2.05029
bench vm          ... : max t = -204.39423
```

The two-key cipher benchmark now passes the key through `black_box`, preventing
the compiler from specializing two constant-key code paths. With that control
the cipher path is below the conventional |t| = 5 leak threshold; the normal VM
data-dependent branch is far above it. The `--constant-time` oblivious mode
executes every block on a fixed pass budget with predicated register writes. The
final straight-line, branchy, and looping measurements are recorded in
`docs/VERIFICATION.md`; all four are below |t| = 5. The in-tree Welch harness
measured `crypto_t=-3.794` and `vm_t=-56.685` for the normal profile.

**Residual:** the normal branchy VM profile is not constant-time. The explicit
mode fixes the instruction stream and memory addresses for the configured pass
budget, uses a fixed oblivious stack scan for private memory, and reports
`LoopBound` for longer loops. No
unbounded constant-time or oblivious-memory guarantee is claimed.

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
differential .sirus.payload equal-byte ratio = 0.0040
differential .sirus segment equal-byte ratio = 0.0243
payload sizes = 45669 / 45607 bytes
```

**Residual:** the interpreter skeleton is reused; 2.43% of the full VM segment
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
- libFuzzer: **789,455 VM and 133,973 lifter runs in 61 s each on the 1.5.9
  tree; 4,883,875 VM / 405,768 lifter cumulative across sessions**, no crash;
- signal reentrancy: SIGALRM handler re-entered the protected function while
  the main thread was executing it; interrupted and reentrant results matched
  native;
- Kani: 5 core + 4 VM bounds harnesses verified;
- Miri: VM library suite 11/11 on the final tree; the larger execution and
  core suites are opt-in and slow;
- malformed-payload suite covers bad count/offset/length/opcode/register/trap/fuel.

---

## Summary

| # | Gate | Status |
|---:|---|---|
| 1 | static body removal / no plaintext | Ghidra + radare2 pass; IDA/Binary Ninja not licensed |
| 2 | MBA resistance | linear forms reduce; GAMBA times out on modular-inverse forms; variable shifts parser-fail; SiMBA reduces inverse forms |
| 3 | DBI resistance | partial; timing/DBI detection impossible/unsafe |
| 4 | taint resistance | design + bypass evidence; no formal taint tool |
| 5 | symbolic resistance | angr 120 s timeout; KLEE 60 s timeout with no completed paths or memory errors |
| 6 | memory dump | entropy/string pass; masked VM state, live constant not observed |
| 7 | patch/forced return | pass |
| 8 | hypervisor | not capable; documented |
| 9 | differential | payload 0.40% equal; full segment 2.43% equal residual |
| 10 | fuzzing | pass across in-tree, libFuzzer, Kani, Miri |

No gate in this report is marked “passed” unless its local command was executed.
Open tools and residuals are listed in `docs/VERIFICATION.md` and
`docs/LIMITATIONS.md`.
