# Architecture and Safety Decisions

---

## ADR-001 — Three-tier `no_std` policy

**Decision:** `sirus-core` and `sirus-vm` are `no_std`, no allocation, no unsafe.
`sirus-binfmt` is `no_std` with intentional `alloc`. `sirus-protector` uses `std`
only at the filesystem/process boundary.

**Reason:** A post-link injector must read/write files and spawn `rustc`. Doing
that without `std` requires unsafe FFI or a C library. The project prioritizes
zero unsafe over literal `no_std` in the build tool. Level 2 lint isolation is
enforced fully in core/VM, partially in binfmt, and explicitly waived in the CLI.

**Evidence:** `docs/CODE_STANDARD_COMPLIANCE.md`.

---

## ADR-002 — `forbid(unsafe_code)` everywhere

**Decision:** Every shipped crate and the generated VM source use
`#![forbid(unsafe_code)]`.

**Consequence:** No `no_mangle`, `link_section`, raw pointers, inline asm, RDTSC,
debug-register access, or native self-code checksum.

**Compensation:** Generated entry thunks are located through their mangled symbol
names; safe `#[used]` function-pointer statics retain them at link time. Payload
integrity and fuel provide the safe anti-tamper subset.

---

## ADR-003 — Freestanding VM compiled with `opt-level=z`

**Decision:** Generated VM source is compiled with `-C opt-level=z`.

**Reason:** At `opt-level=2`, LLVM lowers large fixed-array initialization and
struct copies to `memset`/`memcpy`, which a `-nostdlib` blob cannot resolve.
`opt-level=z` keeps those operations explicit in generated code and produces a
single RX load segment on this toolchain. The blob validator would reject the
build if libc symbols or writable segments appeared.

**Trade-off:** Slower VM code. Correctness and dependency isolation win.

---

## ADR-004 — Derive alias tables on demand

**Decision:** Do not store the 1.2 KiB alias-spec table in the runtime. Store a
compact opcode pool and derive per-alias order/map/endian from the seed on demand.

**Reason:** Large table initialization and copies triggered libc bulk-memory
helpers and increased static plaintext ISA exposure. On-demand derivation keeps
the runtime self-contained and reduces at-rest table structure.

---

## ADR-005 — No native self-checksum / timing anti-debug

**Decision:** Do not implement self machine-code hashing, RDTSC drift, debug
registers, or LFENCE.

**Reason:** All require unsafe or OS-specific APIs, forbidden by the project's
primary constraint.

**Mitigation:** Encrypted payload integrity is arithmetically mixed into the
rolling key; fuel bounds execution; malformed state halts; no unsafe memory path
exists. Residual risk is documented.

---

## ADR-006 — Fixed-capacity stack data structures

**Decision:** Core/VM use `BoundedVec`, `ByteBuf`, and fixed arrays instead of
heap allocation. Large-stack-frame/large-array Clippy lints are allowed with a
reason.

**Reason:** The VM must not allocate; dynamic input must not create unbounded
memory use. Capacity failure is a typed build error or clean VM halt.

**Trade-off:** Upper bounds on function/program size; documented.

---

## ADR-007 — Append-only ELF injection with relocated PHDRs

**Decision:** Add a new PHDR table in an appended R page, add one RX VM LOAD, and
regenerate section headers without relocating original file contents.

**Reason:** Existing loaders accept this (verified on dynamically linked
`/bin/true`); it avoids rewriting original segments or applying relocations.

**Validation:** Independent re-parse, real execution, PT_PHDR update, section-name
table creation when absent.

---

## ADR-008 — Marker mode is raw bytes

**Decision:** Marker discovery is a unique raw byte-pattern search, not a DWARF
or compiler-plugin feature.

**Reason:** Zero dependencies and no source-level compiler integration. Marker
ranges must correspond to valid machine code; ambiguous markers fail the build.

---

## ADR-009 — PE backend is structural-only

**Decision:** Implement PE32+ parsing, section append, checksum, and RVA jump
patching; do not claim Windows execution.

**Reason:** A correct Win64 runtime needs a Windows linker/ABI, loader tests,
CFG/guard-table handling, and exception metadata. Claiming otherwise would be a
demo-level lie.

---

## ADR-010 — Test-only lint exemptions

**Decision:** Test modules may use assertion panics, `expect`, fixed indexing,
and large fixtures. The exemption is declared at crate root with a reason and is
scoped to `cfg(test)`.

**Reason:** Rust's test harness is panic-based; assertion panics are the failure
signal. Shipped code keeps every Level 3 ban.

**Gate:** Clippy `--all-targets -D warnings` must still pass; production builds
exclude the exemption.

---

## ADR-011 — Non-linear MBA with a modular inverse

**Decision:** Add one non-linear wrapper per function: a variable-shift bit
recombination and multiplication by a data-dependent odd number and its
six-step Newton modular inverse.

**Reason:** The linear-only identities were fully reduced by GAMBA and SiMBA.
The wrapper is exact over 64-bit wrapping arithmetic, adds modular multiplication
and variable shifts, and makes the general simplifier time out. It is applied
once per function to keep block bodies and fuel bounded.

**Trade-off:** SiMBA still reduces the inverse form, and GAMBA rejects variable
shifts at parse time rather than proving equivalence. These are measured cost
asymmetries, not a proof of irreducibility.

---

## ADR-012 — External proofs are models, not whole-product proofs

**Decision:** Keep `creusot-std`, `dudect-bencher`, angr, KLEE, and MBA tooling
outside the shipped workspace. Creusot proves boundary models; KLEE compiles the
generated VM with an LLVM-18-era rustc and removes `const` for compatibility.

**Reason:** The shipped crates must stay zero-dependency and `no_std`. The
external tools cannot prove the entire Rust product in one run. Reporting each
result with its exact scope is more honest than presenting a model proof as a
whole-product proof.

**Gate:** `scripts/verify.sh` remains dependency-free; external runs are opt-in
through `scripts/prove.sh` environment flags and their outputs are recorded in
`docs/VERIFICATION.md`.

---

## ADR-013 — Accept the measured VM timing leak

**Decision:** Do not claim constant-time VM execution. Keep the cipher path
dudect-clean and document the data-dependent VM branch as a measured leak.

**Reason:** A general-purpose virtualizer must branch on secret-dependent control
flow and keep virtual registers in memory. Safe Rust cannot add RDTSC, debug
register, or speculative barriers, and a constant-time interpreter would require
executing both sides of every branch and a fully oblivious memory model.

**Residual:** Official dudect-bencher measured the VM branch at max |t| = 358.73,
far above the conventional threshold of 5.
