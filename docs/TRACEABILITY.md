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
| Defeat static decompilation of protected logic | partial | body scrubbed, flattened, encrypted; Ghidra not run |
| Break automated symbolic execution | partial | large states/MBA/encryption; angr not run |
| Invalidate prior work across builds | partial | payload 0.36% equal, ISA/state randomization; full segment 28.6% equal |
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
| MBA expansion | implemented, bounded | `mba.rs`, property tests |
| Opaque predicates / fake branches | implemented | guard/decoy synthesis |
| Constant blinding | implemented | XOR shares in encoder |
| No contiguous sensitive constants | partial by construction | encrypted and blinded; live memory scan open |
| MBA resistance to GAMBA/SiMBA | open/not proven | tools not run |

### Stage 5 — Polymorphic virtual architecture

| Requirement | Status | Evidence |
|---|---|---|
| OS-entropy seed | implemented | `/dev/urandom`, fallback documented |
| Randomized ISA | implemented | shuffled opcode pool, aliases |
| Randomized operand/register encoding | implemented | per-alias order, two reg maps |
| Instruction aliasing | implemented | 4 aliases/semantic |
| Rolling bytecode encryption | implemented | per-byte chained cipher |
| No complete plaintext bytecode in RAM | implemented by design | byte-at-a-time locals; live scan open |
| ISA layout mutation | partial | payload/aliases/maps/states; handler skeleton reused |
| Handler layout mutation | partial | `.sirus` similar bytes 28.6% equal |
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
| Self-checksumming machine code | **not feasible safely** | documented in limitations |
| Hash mixed into rolling key | implemented for payload | effective-key binding |
| Software breakpoint corruption | partial | payload tamper changes key; code breakpoints not detected |
| Timing drift detection | **not feasible safely** | no RDTSC |
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
| Creusot | not run | open |
| AORAI | not run | open |
| cargo-fuzz | run, 66,962 executions | fuzz/ |
| Proptest | external crate prohibited; in-tree property tests implemented | tests |
| cargo-tarpaulin | run, 87.23% | coverage report |
| Loom | not applicable (no shared mutable runtime state) | ADR/architecture |
| dudect-bencher | not implemented | open |
| cargo-show-asm | installed, used | `cargo asm` |
| LFENCE/Spectre fences | not feasible safely | limitations |
| opt-level 3 / LTO / 1 CGU / panic abort / strip | implemented for release | Cargo.toml |
| Ferrocene | not installed | open |

---

## C. `red team` checklist

| # | Requirement | Status | Evidence |
|---:|---|---|---|
| 1 | No readable original logic / no panic strings / no plaintext constants | partial | scrub + strings scan + entropy; Ghidra not run |
| 2 | MBA resists simplification | partial | equivalence tests; GAMBA/SiMBA not run |
| 3 | Uniform handlers, mutate state, detect DBI | partial | per-build geometry; no DBI detection |
| 4 | Taint explosion/laundering | partial | data flow/deep binding; no taint tool |
| 5 | Symbolic explosion | partial | design; angr not run |
| 6 | No decrypted bytecode in memory | partial | no cache by design; live scan open |
| 7 | Deep binding / bypass fails | implemented | tamper and forced-return tests |
| 8 | Hypervisor/debug-register resistance | **not feasible safely** | documented |
| 9 | Differential builds mutate everything | partial | payload 0.36% equal; full segment 28.6% |
| 10 | VM fuzzing no panic/OOB/hang | implemented | in-tree + libFuzzer + Miri + Kani |

---

## D. Open work

1. Coverage from 87.23% to 100%, with branch-level justification.
2. Ghidra/IDA/Binary Ninja headless evaluation.
3. GAMBA/SiMBA/MBA-Blast corpus.
4. angr/KLEE symbolic harness.
5. Live process memory dump scanner.
6. Creusot/AORAI contracts.
7. Ferrocene build validation.
8. Full handler-layout polymorphism.
9. Windows ABI/linker/runtime validation.
10. Optional dudect-style timing measurement (measurement, not a constant-time
    claim).

Any statement that all supplied requirements are fully satisfied is false until
these are closed or explicitly accepted as release exceptions.
