# SIRUS — Master Engineering Plan

**Project:** Zero-Dependency Polymorphic Code Virtualizer in Safe Rust
**Workspace:** `sirus`
**Status:** Authoritative implementation plan; production-prototype scope
**Document owners:** implementation team and adversarial-review team (same repository, separate roles)
**Last updated:** 2026-11-23

---

## Implementation status snapshot

| Milestone | Status |
|---|---|
| M0 skeleton and standards | complete |
| M1 crypto/format primitives | complete |
| M2 decoder/lifter/flags | complete for the documented subset |
| M3 IR/MBA/flattening/encoder | complete |
| M4 reference VM runtime | complete, Kani/Miri/fuzzed |
| M5 ELF injection and VM synthesis | complete, real PIE execution verified |
| M6 multiple functions and data binding | complete, shared-VM e2e test |
| M7 PE/Win64 backend | Wine-tested runtime for leaf subset with branches/loops; native Windows CI passed |
| M8 adversarial suite | partial: in-tree, libFuzzer, Kani, Miri, differential, tamper, bypass, valgrind, Ghidra, radare2, GAMBA/SiMBA/MBA-Blast, angr, KLEE, Creusot, dudect-bencher, constant-time oblivious mode, Windows/Wine |
| M9 production release | **not complete**: per-build handler/engine/entry layout mutation is permuted, but full VM-segment byte equality remains 2.21%; live memory is masked at rest and the snapshot passes; normal VM branches leak timing while `--constant-time` passes; Windows/Wine passes; coverage floor is met. |

See `docs/TRACEABILITY.md` and `docs/VERIFICATION.md` for the exact matrix and
measured evidence.

---

## 0. Document control

This plan is the single source of truth for architecture, scope, safety policy, verification, and release gates. Any implementation choice that weakens a stated invariant must be recorded in `docs/DECISIONS.md` and must be rejected in review unless the plan is amended first.

The three supplied source documents are:

1. `project` — architectural blueprint for the protector and runtime.
2. `code standard` — mandatory Rust hygiene, verification, and release-profile rules.
3. `red team` — adversarial acceptance checklist for the finished protector.

No requirement from those documents is silently dropped. `docs/TRACEABILITY.md` maps every requirement, subsection, and pass criterion to an implementation artifact and a verification artifact. Requirements that cannot be satisfied under the hard constraints are recorded as **explicit safety-driven deviations**, with an alternative control and residual risk.

---

## 1. Mission, scope, and non-goals

### 1.1 Mission

Build a working, reviewable, production-prototype code virtualizer that:

- consumes a compiled Linux x86-64 ELF executable;
- locates an explicitly marked protected function;
- lifts a rigorously bounded x86-64 instruction subset into an internal IR;
- destroys the original control-flow structure by flattening it into randomized state transitions;
- expands sensitive arithmetic through bounded Mixed Boolean-Arithmetic (MBA) rewrites;
- blinds constants into random shares;
- synthesizes a per-build randomized virtual ISA and encrypted payload;
- generates and compiles a freestanding `no_std`, allocation-free, safe-Rust VM runtime;
- injects that runtime and payload into a new executable segment;
- patches the protected function to jump into the synthesized VM;
- destroys the original protected function body;
- supports multiple protected functions sharing one VM instance;
- ships with an adversarial test suite that verifies safety, determinism, polymorphism, integrity failure behavior, and red-team properties;
- uses **zero external crates** in all shipped crates.

### 1.2 Product shape

Two runtime components in one workspace:

1. **Protector engine (build-time CLI).**
   - Runs on the developer's machine.
   - Uses `std` only for filesystem, process, and CLI plumbing.
   - Uses no external crates.
   - Contains no `unsafe`.
   - Must never panic in normal operation; every failure becomes a typed error and a non-zero exit code.

2. **Virtual-machine runtime (injected freestanding stub).**
   - Generated per build.
   - `#![no_std]`, no allocation, no OS imports, no dynamic loader dependencies.
   - No `unsafe`.
   - Fixed-size arrays only.
   - Fail-closed on malformed or tampered payload.
   - Deterministic instruction budget prevents infinite loops.
   - Position-independent machine code linked into a read-execute segment.

### 1.3 In-scope platforms

- Linux x86-64 ELF end-to-end, executed and verified locally.
- ELF `ET_EXEC` and `ET_DYN` (PIE).
- PE32+ / x86-64 parsing, COFF symbol lookup, and runtime section injection.
- Win64 runtime execution is verified under Wine for the strict leaf subset (branches and loops included); native Windows loader/CI validation is a separate experimental line and does not reduce the Linux release gate.

### 1.4 Non-goals for the first release

- Whole-program virtualization.
- Native-code disassembly outside an explicit bounded function range.
- Calls to arbitrary external functions from inside virtualized code.
- Host-pointer dereference inside virtualized code.
- SSE/AVX, floating-point, x87, system instructions, exceptions, or thread-local storage inside virtualized code.
- Full x86-64 coverage.
- A security proof against an attacker with unlimited local time and hardware access.
- Anti-debug or hypervisor detection implemented through unsafe OS APIs.
- Claiming mathematical unbreakability.

These non-goals are enforced by **fail-closed decoding**, not by best-effort behavior.

---

## 2. Hard constraints and conflict resolution

### 2.1 Shipped dependency policy

- Every shipped crate has an empty `[dependencies]` section except path dependencies on other workspace crates.
- No procedural macros, no build-time crates, no runtime crates, no `libc` crate.
- External tools (Kani, Miri, fuzzers, coverage tools) are allowed only as verification infrastructure outside the shipped dependency graph.
- If a verification harness needs an external crate, it lives in a separately excluded tooling crate and cannot be linked into the protector or runtime.

### 2.2 Safe-Rust policy

- `#![forbid(unsafe_code)]` in all shipped crates.
- No `unsafe` blocks, no unsafe attributes, no `no_mangle`, no `link_section`, no raw pointer dereference in shipped code.
- The generated VM entry point is discovered through its mangled symbol in the linked blob instead of using `no_mangle`, preserving `forbid(unsafe_code)`.
- The generated VM is linked with all sections retained; no exported symbol is required for correctness.
- No external binary patching is used to introduce unsafe behavior; the protector performs ordinary file I/O on bytes.

### 2.3 `no_std` policy

- `sirus-core`: `#![no_std]`, no allocation.
- `sirus-vm`: `#![no_std]`, no allocation.
- Generated injected runtime: `#![no_std]`, no allocation, no `main`, no platform calls.
- `sirus-binfmt`: `#![no_std]` parsing plus bounded writer primitives; no unsafe.
- `sirus-protector`: `std` is permitted for process and filesystem boundary code only. It is still safe Rust with panic, indexing, unwrap, and cast bans. This is the only possible way to implement a build-time tool that reads and writes executable files without unsafe syscalls or external crates.

The `code standard` attribute block is applied verbatim-in-spirit to `sirus-core` and `sirus-vm`. The protector applies every lint except `no_std`/`alloc` isolation, which is documented and enforced by module boundaries instead.

### 2.4 Non-negotiable safety invariants

1. No shipped code contains `unsafe`.
2. Every slice access is bounds-checked through checked APIs or proven iterator operations.
3. Every bytecode read validates: payload length, block count, block offset, block length, instruction length, register operand, and fuel.
4. Arithmetic on untrusted values uses wrapping/checked operations; no division or remainder by zero.
5. Shift counts are masked; no shift-overflow panics.
6. No `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, or indexing in shipped code.
7. No floating point in shipped code.
8. Runtime failure is a deterministic halt with a sentinel result, never an exploitable memory operation.
9. The VM cannot access host memory. Its memory model is a private fixed stack.
10. The protector never writes partially validated output files; it writes a temporary file and atomically renames it.

### 2.5 Explicit safety-driven deviations

These items are required by the source documents but are impossible to implement honestly under “safe Rust only, zero unsafe”:

| Document request | Why it conflicts | Alternative control | Residual risk |
|---|---|---|---|
| Hash the VM's own machine code and feed it into the rolling key | Reading arbitrary machine code requires raw pointers or OS APIs, both forbidden | Hash the entire encrypted payload and all static plan material; integrity mismatch alters the rolling key arithmetically | Native patching of the VM engine itself is not detected |
| Detect stepping through timing drift using RDTSC | `_rdtsc` and clock syscalls are unsafe or platform-specific | Deterministic fuel accounting; payload integrity; pointer-free VM design | Human single-stepping is not detected |
| Detect DBI/hypervisor via cache-timing anomalies | Requires unsafe timing primitives, thread/context introspection, or kernel interfaces | Same as above; structural uniformity of state transitions and payload encryption raise analysis cost | A determined DBI analyst can trace semantics |
| Inspect debug registers via exception context frames | Requires unsafe OS-specific FFI | Out of scope; no false claim | Hypervisor-level debugging is not resisted |
| LFENCE/Spectre fences | Intrinsics and inline assembly are unsafe | No secret-dependent native conditional branches in the generated geometry where feasible; `compiler_fence` cannot replace `lfence` and is not claimed as a mitigation | Microarchitectural leakage is not fully mitigated |
| Native Windows runtime end-to-end | Requires a Windows host, loader/CFG validation, and CI | PE parser/injector and Win64 ABI thunk implemented; Wine runtime passes; native Windows CI passed | Native Windows loader/CFG behavior is not yet claimed |

These deviations do not weaken the safe-Rust guarantee. The project will not insert hidden unsafe code to “check a box.”

---

## 3. Threat model

### 3.1 Adversary capabilities

The design assumes an adversary who can:

- read the complete binary, including section headers and symbols;
- run static disassemblers/decompilers (Ghidra, IDA, Binary Ninja);
- run MBA simplifiers and symbolic execution (GAMBA, SiMBA, Triton, angr, Z3);
- trace execution with Intel PIN, Frida, DynamoRIO, QEMU, gdb, or a hypervisor;
- dump process memory at any time;
- patch bytes in file or memory;
- compare two protected builds;
- fuzz the VM payload;
- use custom tooling against the ISA.

### 3.2 Security objectives

- **O1 — Static non-recoverability:** no original function structure, readable constants, or direct semantic handler map survives in the static image.
- **O2 — Dynamic cost:** tracing requires reconstructing a build-specific encrypted ISA and flattened state machine.
- **O3 — Build independence:** two builds of the same input share no meaningful payload bytes and use different opcode assignments, operand orders, register encodings, key material, state ids, block order, MBA shapes, and decoys.
- **O4 — Tamper response:** changing payload bytes silently derives the wrong rolling key; execution produces no valid protected result.
- **O5 — Host safety:** corrupted bytecode cannot cause out-of-bounds access, undefined behavior, panics, unbounded execution, or exploitable crashes.
- **O6 — Deep binding:** protected results are consumed by the host as data, not only as a boolean. A bypass starves the caller of correct values.

### 3.3 Non-objectives

- Protecting against an attacker who owns and instruments the CPU.
- Preventing all dynamic semantic recovery.
- Preventing patch-to-return attacks on callers outside the VM's reach.
- Proving cryptographic security of the custom constructions.

### 3.4 Cost asymmetry

Every security control is evaluated by the incremental analyst effort it creates versus the runtime/size cost it imposes. The project rejects theatrical complexity that is trivially removed by dynamic tracing.

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Build machine                                                            │
│                                                                          │
│  target ELF ─┐                                                           │
│  markers or  ├─► Marker/symbol locator ─► bounded x86-64 decoder          │
│  symbols ────┘                                  │                       │
│                                                 ▼                       │
│                                    Lifted IR + CFG (sirus-core)          │
│                                                 │                       │
│                                                 ▼                       │
│                       CFG flattening + opaque decoys + state ids         │
│                                                 │                       │
│                                                 ▼                       │
│                       MBA expansion + constant blinding + ISA encode     │
│                                                 │                       │
│                                                 ▼                       │
│                    Manifest + rolling encrypted payload + integrity      │
│                                                 │                       │
│  generated Rust VM source ◄── ISA plan/seed ────┘                        │
│           │                                                             │
│           ▼                                                             │
│  rustc freestanding link ─► RX blob (no libc, no relocations)            │
│           │                                                             │
│           ▼                                                             │
│  ELF/PE injector: relocate phdrs, add segment/sections, patch jump      │
│           │                                                             │
│           ▼                                                             │
│  protected executable ─► native verification run                         │
└──────────────────────────────────────────────────────────────────────────┘

Runtime (inside protected executable):
  host call ──► patched function entry ──► generated entry thunk
                                               │
                                               ▼
          fuel-bounded dispatcher ◄─► encrypted manifest / block bodies
                    │
                    ▼
          rolling byte decoder in registers only
                    │
                    ▼
          uniform semantic handlers over fixed register/memory arrays
                    │
                    ▼
          result in RAX ──► host continues (result is data-bound)
```

### 4.1 Workspace layout

```
sirus/
├── Cargo.toml
├── PLAN.md
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── DECISIONS.md
│   ├── TRACEABILITY.md
│   ├── FORMAT.md
│   ├── RED_TEAM.md
│   ├── VERIFICATION.md
│   └── LIMITATIONS.md
├── crates/
│   ├── sirus-core/        no_std compiler core, crypto, IR, x86 lifter, MBA,
│   │                      flattening, ISA plan derivation, payload builder
│   ├── sirus-vm/          no_std reference runtime, shared engine sources
│   ├── sirus-binfmt/      no_std ELF/PE parsers, checked editors
│   └── sirus-protector/   std CLI, entropy, VM source synthesis, rustc driver,
│                          ELF/PE injection orchestration, red-team commands
├── scripts/
│   ├── verify.sh          every local gate
│   ├── red-team.sh        adversarial gates
│   ├── install-tools.sh   external verifier setup
│   └── prove.sh           Kani/Miri/verification subsets
└── tests/                 end-to-end fixtures (if not colocated)
```

### 4.2 Shared-source discipline

The encoder and injected runtime must never drift. The following files are written once and included by both the workspace runtime and the generated blob:

- `shared/sip.rs` — SipHash-2-4.
- `shared/chacha.rs` — ChaCha20 for build entropy expansion.
- `shared/format.rs` — ISA, register, memory, fuel constants and operand layouts.
- `shared/derive.rs` — deterministic per-build ISA table derivation.
- `shared/cipher.rs` — manifest stream construction and rolling body cipher.
- `engine.rs` — reference interpreter.

The protector embeds these source files with `include_str!`, emits them into the generated crate, and the integration test executes the result. A unit test asserts that the embedded source list and the workspace copies are byte-identical.

---

## 5. End-to-end pipeline

### 5.1 Stage A — Input validation

1. Read input bytes with an explicit size ceiling.
2. Detect ELF/PE magic.
3. Validate:
   - class, endianness, machine, header sizes;
   - segment/section ranges;
   - executable segment containing the function;
   - no integer wrap in offset calculations;
   - function lies wholly inside a single executable load segment;
   - function does not overlap another exported function or data symbol;
   - function size is bounded.
4. Reject on any ambiguity.

### 5.2 Stage B — Target discovery

Two supported modes:

- **Symbol mode (primary on ELF):** exact symbol name or unique substring of a `STT_FUNC` symbol; use `st_value` and `st_size`.
- **Marker mode (portable):** user-provided begin/end byte patterns, unique in the file; range must be inside one executable segment; end must follow begin by a bounded amount.

Section mode is a future extension and is not accepted silently.

Validation rules:

- Reject duplicate matches.
- Reject overlapping matches.
- Reject marker patterns that span segment boundaries.
- Reject functions larger than `MAX_FUNCTION_BYTES`.
- Reject functions whose entry is already patched or already inside `.sirus`.

### 5.3 Stage C — Decoding and lifting

A bounded x86-64 decoder translates the function into a typed instruction stream. Unsupported encodings fail the entire build with offset, byte sequence, and reason. The decoder supports at minimum:

- REX prefixes, operand-size and address-size behavior;
- `endbr64`;
- `nop` and multi-byte nop;
- `mov` register/immediate/memory forms;
- `movzx`, `movsx`, `movsxd`;
- `add`, `sub`, `adc`/`sbb` explicitly rejected, `and`, `or`, `xor`, `cmp`, `test`;
- `inc`, `dec`, `neg`, `not`;
- `imul` two/three operand;
- `shl`, `shr`, `sar`, `rol`, `ror` by immediate or `cl`;
- `lea`;
- `push`, `pop`, `leave`;
- `jmp`, `jcc`, `ret`;
- `cmovcc`, `setcc`;
- stack-frame addressing through `rbp`/`rsp`/`r12`/`r13`;
- ModRM/SIB with base, index, scale, and displacement;
- 8/16/32/64-bit operand widths;
- little-endian x86 semantics.

Explicitly rejected: calls, indirect jumps, RIP-relative data loads, segment overrides, x87/SSE/AVX, privileged instructions, IO, atomics, syscalls, retpoline thunks, exception-related flows, and unresolved jump tables.

Semantics:

- x86 registers map to fixed logical VM slots.
- Flags are computed eagerly after flag-setting instructions into dedicated logical slots (`ZF`, `CF`, `SF`, `OF`).
- `inc`/`dec` preserve `CF`, as hardware does.
- 32-bit writes zero-extend; 8/16-bit writes merge.
- `RIP` is not available to virtualized code.
- The initial virtual `RSP` is the top of a private VM stack. Host stack memory is never read or written.
- Stack arguments beyond the sixth are rejected because they live in host memory.
- A virtual `ret` returns the value in virtual `RAX` to the host; it does not pop a host return address.

Output: `LiftedFunction` containing basic blocks, IR ranges, and a validated terminator per block.

### 5.4 Stage D — CFG construction and flattening

1. Discover leaders from entry, branch targets, and conditional fallthroughs.
2. Decode each basic block exactly once.
3. Reject overlap, unreachable bytes inside the protected range, and malformed terminators.
4. Assign a random non-zero 64-bit state id to every block.
5. Assign a scrambled index to every block.
6. Shuffle block order in the payload.
7. Replace every terminator with a state transition:
   - unconditional: `state = mix((target_a ^ target_b), live_value)`;
   - conditional: `state = mix(select(cond, true_target, false_target), live_value)`;
   - return: return `RAX`.
8. The dispatcher has no native switch table. It linearly scans encrypted manifest entries for the current state, making static block map extraction less direct.

### 5.5 Stage E — Semantic camouflage

#### MBA expansion

- IR expressions are built in a bounded arena.
- Rewrites are selected randomly per node with a depth and node budget.
- Verified identities only, using wrapping 64-bit arithmetic:
  - `x + y = (x ^ y) + 2 * (x & y)`
  - `x - y = x + (~y) + 1`
  - `x ^ y = (x | y) - (x & y)`
  - `x & y = (x | y) - (x ^ y)`
  - `x | y = (x ^ y) + (x & y)`
  - `~x = x ^ u64::MAX`
- Every identity has a differential property test over seeded random inputs and exhaustive small-width checks.
- Node budgets prevent code explosion and guarantee termination of the rewriter.

#### Constant blinding

- Immediate constants are split into two or three random shares.
- Shares are reassembled in registers only for the duration of the operation.
- State transit values are stored as XOR share pairs in the instruction stream.
- Manifest state tags are encrypted.
- No original sensitive immediate survives as a contiguous plaintext.

#### Opaque predicates and decoys

- Insert mathematically true guards using runtime-derived values, for example the invariant `(x & 1) * ((x & 1) - 1) == 0`.
- The false path enters a decoy block that performs bounded random MBA work on reserved decoy registers and then rejoins the true successor.
- Decoys never modify live architectural state.
- Decoy count is bounded and configurable.
- Decoys are not claimed to defeat dynamic tracing; they increase static and symbolic cost and are part of a layered defense.

### 5.6 Stage F — Polymorphic ISA synthesis

Per build, derive from a 256-bit seed:

- opcode byte assignment: every semantic receives four unique random opcode bytes;
- operand permutation: every alias has its own operand order;
- register encoding: two independent random encoding tables of 64 unique bytes;
- immediate endianness: per alias;
- alias selection: encoder chooses randomly among four semantically identical encodings;
- virtual register count and mapping remain fixed for runtime determinism, but encoded identities change per build;
- state ids, block order, body encryption keys, manifest keys, and entry shares change per build;
- code layout is perturbed by randomized static data size and generated padding.

The derived tables are **not stored as plaintext tables** in the runtime. Only the seed is stored; tables are rebuilt at runtime. Tampering with the seed breaks payload decryption.

### 5.7 Stage G — Encoding

Manifest:

- header: encrypted block count;
- entry: encrypted state tag, absolute body offset, body length;
- entries are shuffled;
- loading a state scans entries and decrypts each candidate tag;
- malformed count/offset/length halts.

Body:

- each block is a sequence of encoded instructions;
- every byte is stream-encrypted with a rolling state that depends on:
  - global effective key,
  - block state id,
  - absolute payload offset,
  - previous decrypted byte;
- the block ends with `JMP`, `JCC`, `RET`, or `TRAP`;
- no decoded instruction sequence is ever stored in VM memory.

Fuel:

- every executed instruction and every dispatcher scan consumes budget;
- budget is a compile-time constant per build;
- exhaustion halts deterministically with sentinel result `0`.

### 5.8 Stage H — VM synthesis and linking

1. Generate a unique crate name and unique entry function names.
2. Emit:
   - static encrypted payload;
   - static plan seed;
   - static expected integrity hash;
   - split base-key shares;
   - entry-state share pairs;
   - fuel constant;
   - shared modules and engine source.
3. Compile with:
   - `--crate-type=bin`, `no_main`;
   - `-C panic=abort`;
   - `-C opt-level=2` or `3` per profile;
   - `-C overflow-checks=off` with wrapping operations in source;
   - `-C relocation-model=pic`;
   - `-C link-arg=-nostdlib -static -no-pie`;
   - custom linker script producing one RX `PT_LOAD`;
   - `--no-gc-sections` to retain generated entry functions and statics;
   - no build id.
4. Validate the linked blob:
   - exactly one loadable segment;
   - no writable segment;
   - no dynamic relocations;
   - no undefined symbols;
   - no `memcpy`/`memset`/`memmove`/libc references;
   - no panic strings;
   - entry, payload, seed, and hash symbols present;
   - entry within jump range of the protected function.
5. Reject and report if any check fails.

### 5.9 Stage I — ELF injection

1. Parse program headers and section headers.
2. Compute a non-overlapping VM virtual address near the target image.
3. Link the VM blob at that address.
4. Relocate the program-header table to an appended file page.
5. Add a `PT_LOAD` for the program-header page and update `PT_PHDR`.
6. Add a `PT_LOAD` for the VM segment at the exact linked virtual address.
7. Add a `.sirus` executable section and a `.sirus.payload` section for tooling.
8. Append a new section-header table and string table; update `e_shoff`, `e_shnum`, `e_shstrndx`.
9. Patch the function entry:
   - preserve `endbr64` when present for CET compatibility;
   - overwrite five bytes with `E9 rel32`;
   - verify displacement fits signed 32 bits;
   - optionally scrub the remainder of the original protected range with random bytes so the original body is gone.
10. Write atomically.
11. Preserve mode bits.
12. Re-parse the output independently and verify all ranges.

### 5.10 Stage J — PE/Win64 injection

1. Validate DOS, PE, COFF, optional header, and section table.
2. Support PE32+ x86-64.
3. Resolve targets from COFF symbols or unique markers.
4. Add a new executable section in header slack or fail closed.
5. Update `SizeOfImage`, section count, characteristics, and file alignment.
6. Patch entry with `E9 rel32` or an absolute indirect jump if the target is outside 32-bit range.
7. Re-parse and validate.
8. Cross-compile the Win64 VM and verify execution under Wine; native Windows CI is a separate gate.

### 5.11 Stage K — Runtime behavior

At VM entry:

1. Compute integrity hash over the encrypted payload.
2. Derive effective key as `base_key ^ (actual_hash ^ expected_hash)`.
3. Derive ISA tables from the plan seed.
4. Initialize virtual registers:
   - ABI argument registers from host arguments;
   - `RSP` to private stack top;
   - flags to zero.
5. Start at the function's blinded entry state.
6. Dispatch:
   - decrypt manifest count;
   - scan entries;
   - decrypt body bytes as instructions;
   - decode operand roles according to the alias;
   - execute the semantic handler;
   - update fuel;
   - transition state or return.
7. On any malformed state, fuel exhaustion, or trap: return `0` without panicking.

---

## 6. Core data contracts

### 6.1 IR contract

- All values are 64-bit unsigned bit patterns.
- Signed operations interpret two's complement.
- All arithmetic is wrapping unless explicitly compared.
- Register ids are validated before emission.
- Basic-block ids are validated before emission.
- Every block has exactly one terminator.
- Every reachable block is encoded.
- No IR operation can reference host memory.

### 6.2 Bytecode contract

- Opcode byte maps to exactly one semantic via the derived table.
- Operand slots are read in alias-specific order.
- Registers are decoded through one of two alias-specific maps.
- Invalid register encodings halt.
- Every immediate is eight bytes in alias-specific byte order.
- Every block ends in a transition/return/trap.
- Body length is enforced exactly.
- Dispatcher scan is bounded by manifest count and fuel.
- Payload offsets use checked arithmetic.

### 6.3 Integrity contract

- `expected_hash` is computed over the final encrypted payload at build time.
- `base_a ^ base_b` is the intended base key.
- Runtime computes `actual_hash`.
- `effective = base_a ^ base_b ^ actual_hash ^ expected_hash`.
- Intact payload yields the intended key.
- Any modified byte yields a different key and garbage decoding.
- The entropy-derived base key is never stored contiguously.
- The integrity check has no conditional branch on the comparison; mismatch is arithmetically mixed into the key.

### 6.4 ABI contract

- Protected functions use the System V AMD64 integer ABI.
- Up to six integer arguments, one integer return value.
- No floating-point arguments or returns.
- No stack arguments.
- No calls from protected code.
- No host memory access.
- Arguments are initialized into virtual `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`.
- Result comes from virtual `RAX`.
- The patched function and host caller see a normal function call; the VM is jumped to without disturbing the host return address.
- Multiple protected functions share one payload and one engine but have distinct entry thunks and entry states.

---

## 7. Error handling and fail-closed policy

- Every fallible operation returns a typed error.
- No silent repair of malformed binaries or bytecode.
- No partial output left behind: temp file + atomic rename.
- No external process output is trusted; rustc exit status is checked and diagnostics are captured.
- Generated VM has no panic path that can unwind; panic handler is a safe spin loop compiled only as a final guard, and all normal paths halt deterministically.
- Fuzzing asserts no panic, no hang, and bounded fuel.
- On bytecode corruption, returning `0` is intentional and may cause the host to take a different data path; this is part of deep binding.

---

## 8. Verification strategy

### 8.1 Verification principles

- Every security claim is backed by a test or is listed as a residual risk.
- Tests must run locally with no network once tools are installed.
- External tools are pinned and invoked through scripts.
- Flaky tests are quarantined and fixed; they are never retried silently.
- Nightly-only tooling runs under explicit commands; stable CI gates remain authoritative.
- No test may be skipped by default because “it is hard.”

### 8.2 Test layers

#### A. Unit tests

- SipHash reference vector and streaming equivalence.
- ChaCha20 RFC 8439 vector and self-inverse behavior.
- Format exhaustiveness.
- ISA derivation determinism, alias uniqueness, register-map invertibility.
- Cipher symmetry and tamper sensitivity.
- IR builder bounds.
- x86 decoder per supported opcode and prefix combination.
- x86 lifter flags semantics against a hand-coded oracle.
- CFG leader discovery and branch target validation.
- MBA identity properties.
- Constant blinding properties.
- Encoder/decoder round trips.
- ELF/PE header parsing and editing.
- CLI argument parsing.
- Error-path and no-panic tests.

#### B. Differential/property tests (zero-dependency)

- In-tree deterministic PRNG (ChaCha20/SipHash based) generates inputs.
- MBA: for each rewrite at each configured depth, compare original and rewritten expressions over:
  - exhaustive 8-bit inputs;
  - boundary values (0, 1, `u64::MAX`, sign boundaries);
  - seeded random 64-bit inputs.
- Lifting: compare a native helper semantic model with the VM result for every supported operation.
- Encoding: for every semantic and every alias, encode/decode and compare.
- Snapshot tests for format/versioning are deterministic.

#### C. End-to-end tests

- Compile a real Rust sample with `rustc`.
- Protect one and multiple functions.
- Run original and protected binaries over a matrix of inputs.
- Compare stdout/exit codes.
- Verify:
  - VM segment exists, is RX, and is not overlapping;
  - program headers and section headers re-parse;
  - entry jump target is correct;
  - original function body is gone;
  - symbols/payload sections are consistent;
  - output is byte-identical for deterministic seed;
  - output differs for different seed;
  - tampered payload fails closed;
  - truncation produces typed CLI errors, not crashes.

#### D. Fuzzing

- In-tree deterministic fuzz harness over engine `run`:
  - random payloads;
  - structured mutations of valid payloads;
  - corrupted manifests;
  - extreme counts/offsets/lengths;
  - truncated bodies;
  - invalid opcode/register encodings;
  - fuel exhaustion adversarial loops.
- Assertions: no panic, no out-of-bounds, no allocation, deterministic termination, fuel respected.
- Also compile the engine under Miri and run the same corpus.
- `cargo-fuzz` harness is maintained as external verification tooling on the stable engine API; it is not part of shipped dependencies.

#### E. Kani

- Proof harnesses for:
  - manifest count/offset/length validation;
  - register decode bounds;
  - instruction buffer bounds;
  - memory load/store bounds;
  - fuel monotonicity and termination bound;
  - no panic in decode path.
- Kani run as a separate gate; failures block release.

#### F. Miri

- Full workspace unit and integration test subset under Miri.
- All shipped unsafe-free code must be Miri-clean.
- Miri is not applied to the external rustc-compiled injected blob directly; the shared engine is Miri-tested in-crate, the ELF blob is tested natively, and the Win64 blob is tested under Wine.

#### G. Coverage

- `cargo-tarpaulin` with branch coverage.
- Target: at least 85% line coverage, with an expressed goal of high branch coverage on `sirus-core` and `sirus-vm` public paths and error returns.
- Uncovered regions are summarized in `docs/VERIFICATION.md`; 100% is not claimed.
- `cargo-nextest` executes the suite with per-test timeouts where configured.

#### H. Concurrency/race analysis

- Loom is not applicable because the shipped runtime and protector compiler path are single-threaded and contain no shared mutable synchronization.
- A source audit and CI grep enforce absence of `thread`, `Mutex`, `RwLock`, `static mut`, atomics in protected value paths.
- If concurrency is introduced later, Loom becomes mandatory for the new code.

#### I. Side-channel/statistical harness

- `sirus timing` is an external analysis command using std timing only.
- Implements an integer/fixed-point Welch-style comparison without floating point in shipped code.
- Measures VM execution across two input classes and reports drift.
- This is a measurement tool, not a constant-time proof. Results are recorded and regressions are investigated.
- `--constant-time` claims a fixed-instruction oblivious execution mode for the
  configured pass budget; the normal profile is not constant-time.

#### J. Assembly inspection

- `cargo-show-asm`/`objdump` scripts inspect:
  - absence of libc calls in injected blob;
  - absence of panic formatting;
  - RX-only segment;
  - entry thunk code;
  - no stack protector/libc residue;
  - no unexpected relocations.
- Checks fail the release gate if violated.

#### K. Red-team automation

A `sirus redteam` command plus `scripts/red-team.sh` run:

1. Static decompiler smoke test on protected builds (Ghidra headless if installed; otherwise objdump/toolchain checks).
2. MBA simplification corpus.
3. Dynamic trace shape report via available tracing tool; no false pass claims.
4. Taint/flow documentation check.
5. Symbolic execution harness (angr optional; corpus of state transitions mandatory).
6. Memory-dump scan: verify payload remains encrypted; no plaintext strings/constants.
7. Patch/bypass test: forced return values change host result.
8. Debugger/hypervisor: documented non-goal under safe Rust.
9. Differential builds: payload equality ratio near zero; opcode/table/state/order differences.
10. VM fuzzing: no panic, no hang, bounded fuel.

#### L. Static hygiene gates

- `cargo fmt --check`.
- `cargo clippy --all-targets --all-features -- -D warnings` with the documented lint matrix.
- `cargo doc --no-deps` with `missing_docs` denied.
- `cargo audit` and `cargo deny check` (zero dependencies expected).
- grep gates for forbidden patterns: `unsafe`, `unwrap(`, `expect(`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, `as ` casts in shipped code, `f32`/`f64`.
- generated-source check that the VM template compiles under `forbid(unsafe_code)`.

### 8.3 Tool acquisition

`scripts/install-tools.sh` installs or verifies:

- rustup components: `rustfmt`, `clippy`, `miri`, `llvm-tools`, `rust-src`;
- `cargo-nextest`, `cargo-tarpaulin`, `cargo-fuzz`, `cargo-audit`, `cargo-deny`;
- `kani-verifier`;
- `cargo-show-asm`;
- optional: Ghidra, angr/Triton, Intel PIN/Frida/DynamoRIO, valgrind, gdb, strace, perf.

Tools that require network or platform-specific installers are documented with exact commands and skipped only if unavailable, which is reported as an incomplete verification run, not a pass.

### 8.4 Verification matrix

| Claim | Unit | Property | E2E | Fuzz | Miri | Kani | Red team |
|---|---:|---:|---:|---:|---:|---:|---:|
| No unsafe in shipped code | grep + compile | — | — | — | — | — | review |
| No external deps | Cargo metadata | — | — | — | — | — | audit |
| Bounds-safe payload decode | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Terminating VM | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Native semantics preserved | ✓ | ✓ | ✓ | — | — | — | ✓ |
| MBA equivalence | ✓ | ✓ | ✓ | — | ✓ | — | ✓ |
| ISA polymorphism | ✓ | ✓ | ✓ | — | — | — | differential |
| Integrity tamper response | ✓ | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| Injector structural correctness | ✓ | — | ✓ | — | ✓ | — | ✓ |
| Multiple functions share VM | — | — | ✓ | — | — | — | ✓ |
| Original body destroyed | — | — | ✓ | — | — | — | ✓ |
| Decompiler resistance | — | — | smoke | — | — | — | ✓ |
| Memory dump has no plaintext | — | — | ✓ | — | — | — | ✓ |
| Forced-return bypass changes data | — | — | ✓ | — | — | — | ✓ |
| Timing/debug resistance | — | — | — | — | — | — | documented deviation |

---

## 9. Red-team acceptance mapping

Each numbered item follows the supplied `red team` checklist.

1. **Static lifting / decompilation**
   - Controls: no original body, flattened state machine, no native switch table, encrypted payload, randomized ISA, symbols stripped from injected segment, no Rust panic strings in blob.
   - Tests: decompiler smoke run, string scan, entropy/chi-square, section inspection.
   - Gate: no original function bytes or readable VM payload; original symbol still identifies the patched address but not semantics.

2. **MBA simplification**
   - Controls: bounded random linear MBA plus variable-shift recombination, modular multiplication, and a six-step Newton modular inverse.
   - Tests: GAMBA/SiMBA/MBA-Blast corpus from the exact production rewrite hook; local rewriter equivalence over 10,000 random pairs; Z3 equivalence checks on tool output.
   - Gate: every rewrite is exact; linear forms are reduced, while the modular-inverse form times out GAMBA at 20 s and variable shifts parser-fail. SiMBA still reduces the inverse form; this is cost asymmetry, not irreducibility.
   - Residual: a sufficiently powerful solver may reduce expressions; we do not claim otherwise.

3. **DBI / instruction tracing**
   - Controls: uniform handlers, decoy state mutations, per-build geometry, fuel.
   - Tests: structural uniformity report; dynamic trace shape documentation.
   - Residual: safe Rust cannot detect DBI; documented.

4. **Dynamic taint analysis**
   - Controls: arguments feed flags, state selection, and rolling decode geometry; no trivial compare-only path; deep binding.
   - Tests: forced-return/bypass test; taint propagation review of generated IR; secret-dependent branch inventory.
   - Residual: full taint explosion is not proven.

5. **Symbolic execution**
   - Controls: random large state ids, encrypted dispatch, MBA, decoys, bounded loops, data-dependent next-state arithmetic.
   - Tests: angr on the real protected ELF (120 s bounded preimage search) and KLEE on generated VM source (60 s bounded search).
   - Gate: no symbolic preimage was found in either run; this is a bounded negative result, not an unsatisfiability proof.

6. **Live memory dumping**
   - Controls: instructions decrypted byte-by-byte into locals; no decrypted block cache; derived tables in stack memory; payload integrity.
   - Tests: process memory scan for plaintext opcodes/constants/function byte patterns; string scan.
   - Gate: no complete decrypted bytecode image found in mapped memory snapshots during execution.

7. **Byte patching / forced execution**
   - Controls: VM returns data used by host; sample derivation binds output; no boolean-only entry.
   - Tests: NOP/force-return mutation test; host output diverges; patched payload fails integrity.
   - Residual: caller-level bypass is outside VM control unless call sites are also integrated.

8. **Hypervisor / kernel debugging**
   - Controls: none that are honest under safe Rust.
   - Tests: documented non-capability.
   - Gate: no false claim; red-team report explicitly lists this as a residual risk.

9. **Differential binary analysis**
   - Controls: new seed per build; opcode, orders, register maps, state ids, block order, encryption keys, MBA shapes, decoys, padding, entry shares differ.
   - Tests: protect same input twice; compare `.sirus.payload` and full `.sirus`; require payload byte equality near zero and no identical control skeleton.
   - Gate: differential report attached.

10. **Adversarial VM fuzzing**
    - Controls: checked manifest, checked body lengths, decoded register validation, masked shifts, wrapping arithmetic, no division, fuel.
    - Tests: deterministic corpus + mutation fuzz + Miri + Kani.
    - Gate: zero panics, zero hangs, zero OOB, deterministic fuel exhaustion.

---

## 10. Performance and resource budgets

These are starting budgets and release gates for the reference sample. Optimizations may improve them; regressions require review.

- Protected function execution: ≤ 50× native for the reference arithmetic function; VM overhead is expected and acceptable for server-side license/protocol logic.
- VM entry table derivation: bounded and measured; no heap.
- Injected VM blob: ≤ 64 KiB per build (excluding payload configurable ceiling).
- Payload ceiling: 64 KiB by default.
- VM stack: 4 KiB by default.
- Fuel: 2,000,000 default, configurable at protect time.
- Protector end-to-end time on reference sample: ≤ 10 s on the local workstation, excluding first rustc cache warmup.
- End-to-end test runtime in nextest: each test ≤ 60 s timeout.

---

## 11. Milestones and acceptance gates

### M0 — Skeleton and standards
- Workspace, crate boundaries, lint matrix, CI scripts, docs skeleton.
- Gate: `cargo fmt`, `cargo clippy -D warnings`, empty dependency graph, `cargo doc`.

### M1 — Cryptographic and format primitives
- SipHash, ChaCha20, format constants, ISA derivation, cipher.
- Gate: reference vectors, determinism, alias uniqueness, map invertibility.

### M2 — Decoder, lifter, flags
- Supported x86 subset, flag semantics, CFG.
- Gate: opcode corpus, property semantic oracle, unsupported-instruction diagnostics.

### M3 — IR, MBA, flattening, encoder
- Bounded expression arena, rewrites, blinding, state assignment, manifest/body encryption.
- Gate: equivalence properties, round trip, tamper sensitivity.

### M4 — Reference VM runtime
- `no_std` engine, fuel, manifest scan, rolling decode, memory checks.
- Gate: unit/e2e corpus, Miri, Kani, fuzz, no allocation/no unsafe.

### M5 — ELF injection and VM synthesis
- Freestanding rustc link, blob validation, PHDR relocation, section append, jump patch, scrub.
- Gate: real protected ELF runs; re-parse; structural checks.

### M6 — Multiple functions and data binding
- Shared payload/engine, one thunk per function, sample host consumes values.
- Gate: output equality over input matrix; bypass test.

### M7 — PE/Win64 backend
- PE parser/editor/injector with COFF symbols and marker discovery.
- Gate: synthetic round trip plus Wine runtime output equality; native Windows CI passed separately.

### M8 — Adversarial suite
- Red-team CLI, differential builds, memory dump scan, forced-return test, fuzz corpus, scripts.
- Gate: all red-team gates executed; residuals documented.

### M9 — Production prototype release
- Docs complete, tool matrix run, coverage/proof artifacts archived, threat model reviewed, no open P0/P1 findings.
- Gate: final verification transcript in `docs/VERIFICATION.md`.

---

## 12. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| x86 decoder bug miscompiles | critical | fail-closed subset, differential semantic oracle, property tests, fuzz decoder |
| Unsupported real-world function | product limitation | explicit diagnostics; document subset; grow only with tests |
| Safe-Rust prohibits anti-debug | security limitation | document honestly; rely on payload integrity, fuel, geometry |
| Generated blob references libc | build failure | `-nostdlib`, `--no-gc-sections`, symbol/reloc validator, local fixtures |
| PHDR relocation breaks loader | critical | dynamic-PIE fixture tests, PT_PHDR update, kernel run test |
| Payload integrity bypass | tamper | encrypted state/bodies, split keys, data-bound checks; accept local attacker limits |
| VM OOB/panic | critical | no unsafe, checked reads, Kani/Miri/fuzz gates |
| Functional regression in translations | high | native-vs-VM differential matrix |
| Collision of aliases/maps | high | uniqueness assertions at derivation and encode time |
| Jump displacement exceeds 32-bit | build failure | range validation before mutation |
| Section header corruption | tooling/loader issues | append-only section table, independent re-parse |
| Test-only external dependency leaks into shipped graph | policy violation | separate excluded tooling crate; Cargo metadata gate |
| Overfitting to sample | credibility | multiple functions, branch/loop/memory corpus, fuzz |

---

## 13. Documentation deliverables

- `README.md` — build, use, guarantees, constraints.
- `PLAN.md` — this document.
- `docs/ARCHITECTURE.md` — detailed design and diagrams.
- `docs/THREAT_MODEL.md` — adversary, assets, residual risks.
- `docs/FORMAT.md` — ELF/PE injection, payload, ISA, cipher formats.
- `docs/DECISIONS.md` — ADRs, especially safety-driven deviations.
- `docs/TRACEABILITY.md` — every supplied requirement mapped to code/test/status.
- `docs/VERIFICATION.md` — actual tool transcript and coverage evidence.
- `docs/RED_TEAM.md` — attack plan, commands, findings, residuals.
- `docs/POSITIONING.md` — measured comparison with commercial/open-source protectors.
- `docs/LIMITATIONS.md` — unsupported instructions, ABI, OS support, anti-debug.

---

## 14. Definition of done

A release is complete only when:

- [ ] Every crate builds with stable Rust and zero external dependencies.
- [ ] `#![forbid(unsafe_code)]` is present in every shipped crate.
- [ ] No panic, unwrap, indexing, cast, float, or unsafe lint violations remain.
- [ ] Unit, property, e2e, fuzz, Miri, Kani, coverage, and red-team gates have run locally.
- [ ] Protected Linux ELF binaries execute correctly across the input matrix.
- [ ] Multiple functions share one generated VM and remain correct.
- [ ] Differential builds show no meaningful shared payload and randomized ISA/state geometry.
- [ ] Tampered payloads and truncated binaries fail closed.
- [ ] Red-team report documents passes and honest residuals.
- [ ] `docs/TRACEABILITY.md` has no unclassified source requirement.
- [ ] `docs/VERIFICATION.md` contains the final command transcript and artifacts.
- [ ] No P0/P1 review findings are open.
- [ ] All claims match tested behavior; no unsupported security claims remain.

---

## 15. Immediate implementation order

1. Finish shared crypto, format, ISA derivation, and cipher primitives.
2. Build the reference VM engine and its fuzzable API.
3. Build IR, decoder, lifter, and flag semantics.
4. Build MBA/blinding/flattening/encoder.
5. Add ELF and PE format crates.
6. Add VM source synthesis, freestanding rustc link, and blob validator.
7. Add ELF injection and patch path.
8. Add protector CLI.
9. Add end-to-end samples and verification scripts.
10. Run every tool, fix every finding, and write the evidence down.
