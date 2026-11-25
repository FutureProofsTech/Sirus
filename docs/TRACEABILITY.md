# Requirements Traceability

Source documents:

1. `project` — architectural blueprint.
2. `code standard` — mandatory Rust and verification standard.
3. `red team` — adversarial acceptance checklist.

This matrix maps every substantive requirement to implementation and evidence.
Statuses are honest: **implemented**, **partial**, **open**, or **not feasible**
under the safe-Rust/no-unsafe constraint.

---

## A. `project` blueprint

### Core philosophy / threat model

| Requirement | Status | Evidence |
|---|---|---|
| Asymmetric cost, not unbreakability | implemented as stated | `docs/THREAT_MODEL.md`, red-team report |
| Defeat static decompilation of protected logic | partial | body scrubbed, flattened, encrypted; Ghidra/radare2 executed; IDA/BN unavailable |
| Break automated symbolic execution | partial | angr 120 s timeout, KLEE 60 s timeout, no completed symbolic path |
| Invalidate prior work across builds | partial | payload 0.40% equal, ISA/state randomization, handler/engine/entry layout mutation; full segment 2.21% equal |
| Two components in one workspace | implemented | core/vm/binfmt/protector crates |
| Zero external libraries | implemented | `cargo tree`, `cargo deny` |

### Stage 1 — Binary ingestion and marker discovery

| Requirement | Status | Evidence |
|---|---|---|
| Raw ELF/PE parsing without third-party libs | implemented | `sirus-binfmt` |
| Header validation | implemented | strict ELF/PE parsers and tests |
| Marker discovery | implemented | `--marker-begin/--marker-end`, marker e2e test |
| Symbol-based function location | implemented | exact/unique-substring selectors |
| Section carving into new executable segment | implemented | ELF injector; PE `.sirus` section |
| Unsupported/ambiguous input fails | implemented | typed errors, malformed tests |

### Stage 2 — Lifting into IR

| Requirement | Status | Evidence |
|---|---|---|
| Abstract, platform-independent actions | implemented | `ir.rs` typed operations |
| CFG/basic-block construction | implemented | lifter leader discovery/validation |
| Hardware register/flags model | implemented | virtual registers, eager flags |
| Bounded decoder, no full disassembler | implemented | strict subset decoder |
| Target extraction via marker boundaries | implemented | marker test |

### Stage 3 — Structural destruction / flattening

| Requirement | Status | Evidence |
|---|---|---|
| Detach blocks and flatten | implemented | random global state ids, shuffled blocks |
| Large cryptographic state ids | implemented | 64-bit random non-zero states |
| Dynamic next-state calculation | implemented | runtime mix; conditional select |
| Decoy/trap state for forced jumps | implemented for selected blocks | opaque guards/decoy blocks |
| No native switch table | implemented | manifest scan |

### Stage 4 — Semantic camouflage

| Requirement | Status | Evidence |
|---|---|---|
| MBA expansion | implemented, bounded, linear + non-linear | `mba.rs`, fixed/random property tests |
| Opaque predicates / fake branches | implemented | guard/decoy synthesis |
| Constant blinding | implemented | XOR shares in encoder |
| No contiguous sensitive constants | partial by construction | encrypted and blinded; live memory scan finds transient VM register values |
| MBA resistance to GAMBA/SiMBA | partial | GAMBA times out on modular-inverse forms; variable shifts parser-fail; SiMBA reduces inverse forms |

### Stage 5 — Polymorphic virtual architecture

| Requirement | Status | Evidence |
|---|---|---|
| OS-entropy seed | implemented | `/dev/urandom`, fallback documented |
| Randomized ISA | implemented | shuffled opcode pool, aliases |
| Randomized operand/register encoding | implemented | per-alias order, two reg maps |
| Instruction aliasing | implemented | 4 aliases/semantic |
| Rolling bytecode encryption | implemented | per-byte chained cipher |
| No complete plaintext bytecode in RAM | implemented by design | byte-at-a-time locals; live scan finds transient register values |
| ISA layout mutation | partial | payload/aliases/maps/states; handler skeleton reused |
| Handler layout mutation | implemented at arm-order level | `.sirus` similar bytes 2.21% equal |
| Build-specific static data | implemented | seed/payload/hash/entry shares |

### Stage 6 — VM synthesis and injection

| Requirement | Status | Evidence |
|---|---|---|
| Safe Rust, zero-dependency VM | implemented | `sirus-vm`, generated `forbid(unsafe_code)` |
| No heap allocation | implemented | fixed arrays, no alloc |
| Bounds-checked memory | implemented | safe indexing, Kani/fuzz/Miri |
| Generated per-build Rust VM source | implemented | `vmgen.rs`, `--emit-source` |
| Rust compiler invocation | implemented | freestanding rustc link |
| Position-independent VM code | implemented | `relocation-model=pic`, validator |
| New executable section/segment | implemented | ELF append-only injection |
| Original bytes overwritten with jump/junk | implemented | `E9`, random scrub |
| Multiple functions share one VM | implemented | e2e shared-payload test |
| Multiple function entry offsets | implemented | entry states/thunks |

### Stage 7 — Active anti-tamper / integrity

| Requirement | Status | Evidence |
|---|---|---|
| Self-checksumming machine code | implemented for Linux and Windows hardened builds | linked text hash + tamper tests |
| Hash mixed into rolling key | implemented for payload | effective-key binding |
| Software breakpoint corruption | partial | payload tamper changes key; code breakpoints not detected |
| Timing drift detection | hardened tier only | LFENCE/RDTSC budget; dudect evidence |
| Silent wrong behavior rather than obvious branch | implemented | tamper returns wrong results, no branch |
| Fuel limit | implemented | deterministic exhaustion |

### Engineering realities

| Requirement | Status |
|---|---|
| Selective protection only, documented | implemented (`LIMITATIONS`) |
| Shared VM per executable | implemented |
| Build-pipeline integration | implemented CLI/scripts |

---

## B. `code standard`

### Level 1

| Lint group | Status | Evidence |
|---|---|---|
| `clippy::all/pedantic/nursery/cargo` | implemented all crates | Cargo lint tables + `-D warnings` |

### Level 2

| Requirement | core | vm | binfmt | protector |
|---|---|---|---|---|
| `alloc_instead_of_core` | enforced | enforced | waived (alloc intentional) | waived |
| `std_instead_of_core` | enforced | enforced | enforced | waived |
| `std_instead_of_alloc` | enforced | enforced | waived | waived |
| `no_std` | yes | yes | yes | no (safe std boundary) |

See `docs/CODE_STANDARD_COMPLIANCE.md` and ADR-001.

### Level 3

| Lint | Status |
|---|---|
| unwrap/expect/indexing/panic/todo/unimplemented/unreachable | enforced in shipped code; test-only reasoned exemption |
| absolute unsafe ban | `forbid(unsafe_code)` all shipped/generated code |

### Level 4

| Lint | Status |
|---|---|
| as/cast-lossless/cast-truncation/cast-wrap/float | enforced all crates |

### Level 5

| Lint | Status |
|---|---|
| missing_inline_in_public_items | enforced |
| exhaustive_structs | enforced (non_exhaustive/private) |

### Paranoia additions

| Requirement | Status |
|---|---|
| no panic macros | enforced by Clippy and code |
| Result error propagation | implemented |
| bounds verification | enforced |
| no unsafe | enforced |

### Verification suites

| Tool/requirement | Status | Evidence |
|---|---|---|
| Kani / SMT | run, 7 harnesses pass | `docs/VERIFICATION.md` |
| Creusot | run, 3 boundary models proved | `verification/creusot`, `scripts/creusot-check.sh` |
| AORAI | installed (Frama-C 33.0); C-only, not applicable | `docs/VERIFICATION.md` |
| cargo-fuzz | run, 1,056,362 final-tree executions (2,929,049 cumulative) | fuzz/ |
| Proptest | external crate prohibited; in-tree property tests implemented | tests |
| cargo-tarpaulin | run, 85.05% (above 85% floor) | coverage report |
| cargo-llvm-cov | run, independent coverage | `docs/VERIFICATION.md` |
| Loom | not applicable (no shared mutable runtime state) | ADR/architecture |
| dudect-bencher | run; cipher below \|t\|=5, VM branch leaks | `verification/dudect` |
| cargo-show-asm | installed, used | `cargo asm` |
| LFENCE/Spectre fences | not feasible safely | limitations |
| opt-level 3 / LTO / 1 CGU / panic abort / strip | implemented for release | Cargo.toml |
| Ferrocene | not installed; customer authentication unavailable | open |

---

## C. `red team` checklist

| # | Requirement | Status | Evidence |
|---:|---|---|---|
| 1 | No readable original logic / no panic strings / no plaintext constants | partial | Ghidra/radare2 scoped evidence; host std strings remain outside `.sirus` |
| 2 | MBA resists simplification | partial | GAMBA timeout on inverse forms; variable shifts parser-fail; SiMBA reduces inverse |
| 3 | Uniform handlers, mutate state, detect DBI | partial | per-build handler/engine/entry layout mutation and geometry; DBI/timing detection not feasible in safe Rust |
| 4 | Taint explosion/laundering | partial | data flow/deep binding; no taint tool |
| 5 | Symbolic explosion | partial | angr and KLEE bounded timeouts; not proofs |
| 6 | No decrypted bytecode in memory | partial | no body cache; VM registers/memory masked at rest; live constant scan passes |
| 7 | Deep binding / bypass fails | implemented | tamper and forced-return tests |
| 8 | Hypervisor/debug-register resistance | **not feasible safely** | documented |
| 9 | Differential builds mutate everything | partial | payload 0.40% equal; full segment 2.21%; handler arms and engine/entry layout mutated per build |
| 10 | VM fuzzing no panic/OOB/hang | implemented | in-tree + libFuzzer + Miri + Kani |

---

## D. External evidence and accepted boundaries

1. Native Windows runtime, `/guard:cf`, PDB/map targeting, and ABI-matrix CI
   execution are covered. Runtime exception propagation through a protected leaf
   remains out of scope; direct calls between selected protected functions are
   now guest-state transitions and are tested, while external calls fail closed.
2. Byte-level VM-segment indistinguishability beyond the current 2.21% equality;
   handler/engine/entry layout order is already permuted per build.
3. Optional hardened-tier controls (RDTSC, debug registers, native self-checks,
   LFENCE) are permanently out of scope for the safe tier under ADR-020.

The safe-tier prototype is complete for the documented Linux ELF path, the
Wine-tested and native Windows-tested Win64 path, and the fixed-pass
constant-time mode. Native Windows and `/guard:cf` gates were executed in
GitHub Actions.
