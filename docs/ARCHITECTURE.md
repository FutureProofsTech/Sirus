# Sirus Architecture

This document describes the implemented architecture. The forward-looking
engineering plan is [`../PLAN.md`](../PLAN.md); exact measured evidence is in
[`VERIFICATION.md`](VERIFICATION.md).

---

## 1. Crate graph

```text
sirus-core (no_std, no alloc, no unsafe)
├── shared/sip.rs          SipHash-2-4
├── shared/chacha.rs       ChaCha20 build entropy expansion
├── shared/format.rs       shared ISA constants, registers, operand roles
├── shared/derive.rs       per-build ISA derivation
├── shared/cipher.rs       manifest stream, rolling body cipher, integrity
├── decode.rs              fail-closed x86-64 decoder
├── lifter.rs              x86 → IR, flags, CFG
├── ir.rs                  fixed-capacity IR/CFG/buffers
├── mba.rs                 bounded expression arena and MBA rewrites
├── encode.rs              IR → randomized ISA bytes
└── program.rs             flattening, decoys, manifest, final payload

sirus-vm (no_std, no alloc, no unsafe)
└── engine.rs              reference VM; embedded verbatim into generated VM

sirus-binfmt (no_std + alloc, no unsafe)
├── elf.rs                 ELF64 parser/editor, injection, jump patching
└── pe.rs                  PE32+ parser/editor, section injection

sirus-protector (std boundary, safe Rust)
├── cli.rs                 argument parsing
├── entropy.rs             OS entropy, seed/hex helpers, scrub randomness
├── vmgen.rs               generated source, freestanding link, blob validation
├── pipeline.rs            target selection, lifting, compile, inject, patch, scrub
└── main.rs                command dispatch
```

`fuzz/` is a separate excluded tooling crate using libFuzzer; it is not part of
the shipped dependency graph.

---

## 2. Build-time pipeline

```text
input ELF
  │
  ├─ ELF parse/validate
  ├─ selector resolution (exact symbol, unique substring, or markers)
  ├─ executable-range and overlap validation
  │
  ├─ decoder (strict subset) ─► IR basic blocks ─► flag computations
  │
  ├─ flattening: random 64-bit state ids, shuffled blocks
  ├─ opaque guard/decoy synthesis for selected unconditional jumps
  ├─ MBA expansion + constant blinding
  ├─ ISA encoding: random opcode aliases, operand orders, reg maps, endianness
  ├─ manifest + rolling-encrypted bodies + integrity hash
  │
  ├─ generated Rust VM source
  ├─ rustc freestanding link at chosen VA (opt-level=z, no libc)
  ├─ blob validation: one RX LOAD, no W, no relocs, no undefined symbols
  │
  ├─ ELF injection: relocated PHDR table, added RX segment, new sections
  ├─ patch selected function entries to VM thunks (`E9 rel32`, endbr64 preserved)
  └─ scrub original function bodies with random bytes
```

The target is never relocated. The program-header table is moved to an appended,
read-only mapped page; existing LOAD segments are untouched.

---

## 3. x86-64 lifting

The decoder is deliberately not a general disassembler. It recognizes instruction
lengths and operand structure only for the supported subset. Any unknown form is
a build error with an offset and reason.

Registers map to fixed logical slots:

- `RAX..R15`: 0..15
- `ZF`, `CF`, `SF`, `OF`: 16..19
- `ZERO`, `ONE`: 20..21
- compiler scratch: 24..59
- lifter scratch: 60..63

Flag semantics are computed **eagerly** into virtual registers after every
supported flag-setting instruction. `inc`/`dec` preserve `CF`; shifts and `imul`
mark flags unknown and reject a dependent `jcc` until a supported flag setter
overwrites them. Flag knowledge resets at every basic-block boundary, so
cross-block flag liveness fails closed.

Memory operands resolve through base, index, scale, and displacement into a
private byte-addressable stack. RIP-relative and absolute addressing are
rejected. The six register arguments are initialized in the virtual System V
registers; result comes from virtual `RAX`.

---

## 4. IR and flattening

- Fixed-capacity `BoundedVec`/`ByteBuf`; no allocation.
- Two-address typed IR operations.
- One terminator per basic block.
- Leaders are discovered from entry, branch targets, and conditional
  fallthroughs; overlapping instruction ownership is rejected.
- Every block gets a random non-zero 64-bit state id.
- Block order is shuffled in the manifest.
- Each block ends with a flattened transition, return, or trap.
- Conditional state selection uses a runtime register plus canceling mix
  arithmetic, so native switch-table structure is absent.
- Multiple functions share one payload and one VM; each gets a blinded entry
  state and its own entry thunk.

---

## 5. MBA and constant blinding

Expressions are built in a bounded arena and rewritten with exact 64-bit
wrapping identities:

- `x + y = (x ^ y) + 2*(x & y)`
- `x - y = x + ~y + 1`
- `x ^ y = (x | y) - (x & y)`
- `x & y = (x | y) - (x ^ y)`
- `x | y = (x ^ y) + (x & y)`
- `~x = x ^ u64::MAX`

Depth and node budgets prevent explosion. Constant leaves are emitted as two
random shares reassembled with XOR. MBA equivalence is tested locally over
boundary values and seeded random inputs.

Opaque guards use the invariant `(x & 1) * ((x & 1) - 1) == 0`. The false path
executes a decoy block on scratch registers and rejoins the true successor. The
guard never changes live architectural state.

---

## 6. Polymorphic ISA

Per build, a 256-bit seed derives:

- 256-byte shuffled opcode pool;
- four aliases per semantic operation (176 opcodes total);
- per-alias operand order;
- per-alias register-map variant;
- per-alias immediate endianness;
- two independent 64-register encoding maps;
- manifest integer endianness;
- rolling keys, state ids, block order, entry shares, MBA shapes, decoys.

Alias operand layouts are derived from the seed once per VM invocation into a
fixed 1.2 KiB runtime table, then indexed per instruction. They are not serialized
into the executable. The cached table removes a per-instruction SipHash/shuffle
cost while keeping the static image free of a plaintext alias table.

---

## 7. Payload

```text
payload =
  encrypted manifest header (count)
  encrypted manifest entries (state, absolute body offset, body length), shuffled
  encrypted block bodies
```

- Manifest keystream is position-addressed.
- Bodies use a rolling cipher seeded by global key, block state, and absolute
  offset; each byte depends on position and the previous decoded byte.
- Decrypted instructions exist only in locals; no decrypted body cache exists.
- Virtual registers and private stack bytes are masked at rest with per-invocation
  keys; the VM unmasks only the operand consumed by the current instruction.
- The runtime computes a SipHash integrity hash over the final encrypted payload.
- Effective key = `base_a ^ base_b ^ actual_hash ^ expected_hash`.
  Intact payload yields the intended key; any modified byte changes the key and
  corrupts decoding.
- `base_a`/`base_b` are split shares in the generated source.
- Fuel bounds every dispatcher scan and instruction.

---

## 8. Runtime

`engine::execute`:

1. Derives ISA tables from the seed.
2. Derives effective key from the payload hash.
3. Initializes virtual registers and private stack.
4. Scans the encrypted manifest for the current state.
5. Decrypts one instruction byte at a time.
6. Resolves alias operand order and register encoding.
7. Executes the semantic operation.
8. Transitions, returns, traps, or halts on malformed input/fuel exhaustion.

All accesses are checked. There is no unsafe code, no allocation, no host memory
access, no division, no unchecked shifts, and no panic path in normal execution.
The generated panic handler is a final no_std guard only.

---

## 9. Freestanding VM synthesis

The generated source includes:

- shared ISA/cipher/derive modules;
- engine;
- payload, seed, expected hash, key shares, entry states, fuel;
- one `extern "C"` thunk per protected function;
- safe `#[used]` function-pointer statics to retain thunks without `no_mangle`.

It is compiled with:

- `--edition=2021 --crate-type=bin`
- `#![no_std] #![no_main] #![forbid(unsafe_code)]`
- `panic=abort`, `codegen-units=1`, `relocation-model=pic`, `overflow-checks=off`
- `opt-level=z` (also prevents libc `memcpy` synthesis for current runtime)
- `-nostdlib -static -no-pie`, custom linker script, `--no-gc-sections`
- single RX `PT_LOAD`, `.data/.bss/.got/relocs` discarded

The blob validator rejects undefined symbols, relocations, writable load
segments, missing symbols, wrong payload/seed, or entries outside the segment.

---

## 10. ELF injection geometry

Original file is preserved. Appended layout:

```text
[original bytes]
[pad to page]
[new program-header table]     -> mapped read-only at phdr_vaddr
[pad to page]
[VM segment bytes]             -> mapped R+X at linked vm_vaddr
[new .shstrtab]
[new section-header table]
```

- `PT_PHDR` updated to the new table.
- One new R LOAD maps the table page.
- One new RX LOAD maps the VM.
- `.sirus` covers the VM segment; `.sirus.payload` covers the encrypted payload.
- Section header table and names are regenerated; a name table is created if the
  input lacked one.
- Function patch is `E9 rel32`; `endbr64` is preserved for CET compatibility.
- The remainder of each original function is overwritten with deterministic
  random bytes.
- Output is written to a temporary file in the destination directory, permissions
  copied from the input, then atomically renamed.

---

## 11. PE backend

PE32+ is parsed strictly: DOS/COFF/optional headers, AMD64 machine, section
alignment, section bounds, RVA/file mapping, checksum, and COFF symbols. Injection
appends one executable `.sirus` section, updates section count/size-of-image,
recomputes the PE checksum, patches one RVA-relative jump per protected
function, and overwrites the original body with keyed junk.

The Win64 runtime is generated with `rustc --target x86_64-pc-windows-gnu`, linked
with `lld-link` and a local stack-probe shim, then its `.text`/`.rdata` bytes are
embedded as one RX section. Function arguments are translated from the Windows
x64 ABI to the VM's internal array at the entry thunk. The strict leaf subset,
including branches and loops, is verified under Wine. Native Windows loader/CFG
validation, exception metadata, signing, imports/TLS, and Windows anti-debug are
not yet implemented or claimed.

### 11.1 Constant-time oblivious execution

`--constant-time` selects a second execution path in the embedded engine. It
parses the manifest once, then executes every manifest block on every pass. A
frontier mask array carries the active path; register writes are selected with
`(new & active) | (old & !active)`. A `JCC` produces both successor targets and
enqueues each with the condition mask or its complement, so the instruction
stream does not depend on the branch decision. Returns and traps are accumulated
under the active mask.

Programs with no cycles use their exact maximum block count as the fixed pass
bound. Any program containing a loop uses `--constant-time-passes` (default 256);
a frontier that does not converge returns `LoopBound`. Private `Load`/`Store` is rejected because no
oblivious memory model is implemented. The normal profile remains branchy and is
not constant-time.

---

## 12. Threading and reentrancy

The VM uses only per-invocation stack state. It has no mutable global engine
state; separate host threads calling protected functions do not share VM
registers or memory. The immutable payload/tables seed are read-only. This makes
Loom-style synchronization testing inapplicable to the current design; a source
gate rejects shared mutable runtime state if introduced.
