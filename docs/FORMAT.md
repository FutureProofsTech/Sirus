# Sirus Wire and Injection Formats

All values are little-endian unless explicitly randomized per alias. The shared
source of truth is `crates/sirus-core/src/shared/format.rs`; compiler and runtime
include the same module.

---

## 1. Virtual registers

| Slot | Meaning |
|---:|---|
| 0..15 | `RAX`, `RCX`, `RDX`, `RBX`, `RSP`, `RBP`, `RSI`, `RDI`, `R8`..`R15` |
| 16 | `ZF` |
| 17 | `CF` |
| 18 | `SF` |
| 19 | `OF` |
| 20 | constant zero |
| 21 | constant one |
| 24..59 | compiler scratch |
| 60..63 | lifter scratch |

Virtual memory is a fixed 4 KiB byte-addressable stack starting at address 4080.
No host memory is addressable.

---

## 2. Semantic operations

| ID | Name | Canonical operands | Semantics |
|---:|---|---|---|
| 0 | NOP | — | no operation |
| 1 | MOV_RR | dst, src | move |
| 2 | MOV_RI | dst, imm | move immediate |
| 3 | ADD_RR | dst, src | wrapping add |
| 4 | ADD_RI | dst, imm | add immediate |
| 5 | SUB_RR | dst, src | wrapping subtract |
| 6 | SUB_RI | dst, imm | subtract immediate |
| 7 | MUL_RR | dst, src | wrapping multiply |
| 8 | AND_RR | dst, src | bitwise AND |
| 9 | AND_RI | dst, imm | AND immediate |
| 10 | OR_RR | dst, src | bitwise OR |
| 11 | OR_RI | dst, imm | OR immediate |
| 12 | XOR_RR | dst, src | bitwise XOR |
| 13 | XOR_RI | dst, imm | XOR immediate |
| 14 | NOT_R | dst | bitwise NOT |
| 15 | NEG_R | dst | wrapping negation |
| 16 | SHL_RR | dst, count | left shift, count masked to 63 |
| 17 | SHL_RI | dst, imm | left shift |
| 18 | SHR_RR | dst, count | logical right shift |
| 19 | SHR_RI | dst, imm | logical right shift |
| 20 | SAR_RR | dst, count | arithmetic right shift |
| 21 | SAR_RI | dst, imm | arithmetic right shift |
| 22 | ROTL_RR | dst, count | rotate left |
| 23 | ROTL_RI | dst, imm | rotate left |
| 24 | ROTR_RR | dst, count | rotate right |
| 25 | ROTR_RI | dst, imm | rotate right |
| 26 | CMPEQ_RR | dst, a, b | boolean equality |
| 27 | CMPLTU_RR | dst, a, b | unsigned less |
| 28 | CMPLTS_RR | dst, a, b | signed less |
| 29 | CMPLEU_RR | dst, a, b | unsigned less-or-equal |
| 30 | CMPLES_RR | dst, a, b | signed less-or-equal |
| 31 | SELECT_RRRR | dst, cond, a, b | select |
| 32 | LOAD8 | dst, addr | byte load, zero-extended |
| 33 | LOAD16 | dst, addr | 16-bit load |
| 34 | LOAD32 | dst, addr | 32-bit load |
| 35 | LOAD64 | dst, addr | 64-bit load |
| 36 | STORE8 | addr, src | byte store |
| 37 | STORE16 | addr, src | 16-bit store |
| 38 | STORE32 | addr, src | 32-bit store |
| 39 | STORE64 | addr, src | 64-bit store |
| 40 | JMP | target, mix | `target + mix - mix` state transition |
| 41 | JCC | cond, true, false, mix | conditional state transition |
| 42 | RET | value | return |
| 43 | TRAP | — | clean halt |

Bounds violations, invalid shifts (after masking), invalid registers, invalid
opcodes, and address overflow halt with `BadPayload`.

---

## 3. Instruction encoding

Each semantic has four aliases. Every alias has:

- a unique opcode byte from a shuffled 256-byte pool;
- its own permutation of canonical operand roles;
- register-map variant 0 or 1;
- immediate byte-order flag.

Wire format:

```text
opcode byte
operands in alias order:
  register role -> one encoded register byte
  immediate role -> eight bytes, little- or big-endian per alias
```

Register operand bytes are decoded through one of two independent 256-entry
tables; invalid encodings halt.

Alias selection is random per instruction. This defeats simple opcode frequency
analysis and makes two builds differ even for identical semantics.

---

## 4. Manifest

```text
offset 0       8 bytes   encrypted block count
offset 8       16 bytes  encrypted entry (repeated `count` times, shuffled)
```

Each 16-byte entry:

```text
+0   8 bytes  state id
+8   4 bytes  absolute payload offset of body
+12  4 bytes  body length
```

Manifest bytes use a position-addressed SipHash-derived keystream and per-build
integer endianness. Entries are shuffled independently of body order.

Limits: count ≤ 256, manifest/body must lie within payload, body length > 0.

---

## 5. Body cipher

For each block:

```text
state = global_key ^ rotl(block_state, 17) ^ body_offset ^ BODY_DOMAIN
```

For each byte at absolute offset `i`:

```text
mixed = body_mix(state ^ rotl(i,23) ^ previous_plain)
state = rotl(state,7) + rotl(mixed,31) ^ i ^ previous_plain
cipher = plain ^ low8(mixed)
```

`body_mix` is a SplitMix64-style ARX avalanche function. SipHash-2-4 remains the
manifest, integrity, and key-derivation primitive; the body stream is an
obfuscation stream, not a MAC. Encryption and decryption are symmetric. Bytes are
decoded sequentially into locals; no plaintext body buffer exists in the
runtime.

---

## 5b. Generated decode table

Generated runtimes embed an encrypted decode-table image containing:

```text
semantic_of_opcode[256]
alias_of_opcode[256]
reg_decode[2][256]
aliases[160] (opcode, order[4], reg_map, endian, reserved)
manifest_big_endian
```

The bytes are XOR-masked with a per-build ARX stream keyed by
`SipHash24(seed domain)`. `DecodeTables::from_encrypted` verifies length and
decrypts into a fixed stack table once per protected invocation. Bounds and
semantic/register filters are applied at use sites; malformed tables fail closed.

---

## 5c. Masked execution state

Before execution, the VM derives a register mask for each virtual register and a
private-memory keystream from the effective payload key. Register and memory
reads XOR the mask back in; writes XOR it out. The initial stack fill is also
stored masked. A passive process dump therefore sees masked values, not the
plaintext constants used by the protected function. The key is in generated
code, so this is an at-rest masking layer, not cryptographic isolation from an
attacker who can execute/debug the VM.

---

## 6. Integrity binding

```text
actual_hash   = SipHash24(seed[16..32] derived key, encrypted_payload)
effective_key = base_a ^ base_b ^ actual_hash ^ expected_hash
```

At build time `expected_hash == actual_hash`. At runtime, any payload mutation
changes `effective_key`; manifest and body decryption then produce invalid
structures. No comparison branch is used.

`base_a` and `base_b` are random split shares of the intended key in generated
source. Fuel bounds execution.

---

## 7. Generated entry thunks

For each protected function, generated source defines a safe `extern "C"`
function with six `u64` arguments and a unique mangled name. It calls
`engine::execute(..., entry_index, args)` and returns `.value`. A safe `#[used]`
function-pointer static keeps the thunk alive through linking without
`no_mangle`.

The ELF patcher finds these thunks in the blob symbol table and patches each
target function with `E9 rel32`.

---

## 8. ELF injection layout

New segments:

| Segment | Flags | Content |
|---|---|---|
| PHDR page LOAD | R | relocated program-header table |
| VM LOAD | R+X | VM code, read-only tables, encrypted payload |

New sections:

- `.sirus` — PROGBITS, ALLOC+EXECINSTR, whole VM segment.
- `.sirus.payload` — PROGBITS, ALLOC, encrypted payload only.

Program header table is appended and `PT_PHDR` updated. Section header table and
section-name string table are regenerated; `.sirus` names are created even for
inputs without a name table.

Function patch:

- preserve `F3 0F 1E FA` (`endbr64`) when present;
- write `E9 <rel32>` at entry or after `endbr64`;
- reject if the displacement does not fit;
- overwrite the remainder of the original function with deterministic random
  bytes unless `--no-scrub`.

Output is written atomically with input permissions preserved.

---

## 9. PE injection layout

PE32+ only. A `.sirus` section is appended:

- name `.sirus`;
- `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`;
- virtual address aligned to `SectionAlignment`;
- raw offset aligned to `FileAlignment`;
- `SizeOfImage` updated;
- section count updated;
- PE checksum recomputed;
- optional RVA-relative `E9` patch.

Header slack for one section header is required. Runtime execution is not yet
validated for Windows.

---

## 10. ABI

- System V AMD64 (Linux) for the working ELF backend.
- Up to six integer arguments in `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`.
- One integer result in `RAX`.
- No floating-point arguments or results.
- No stack arguments.
- No calls, no host pointers, no host memory.
- The patched target is entered by a normal host call; the `jmp` preserves the
  host return address, and the VM thunk returns normally.
