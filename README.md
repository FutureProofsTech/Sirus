# SIRUS (Super Sirus)

**Zero-dependency polymorphic code virtualizer in Safe Rust.**

**Release:** `1.5.0-hardened` — see [`RELEASE.md`](RELEASE.md) and [`CHANGELOG.md`](CHANGELOG.md).

Sirus takes a compiled Linux x86-64 ELF, lifts a selected function into an
internal IR, flattens its control flow, expands sensitive arithmetic through
bounded linear and non-linear MBA, encodes it into a per-build randomized
encrypted ISA, synthesizes a freestanding `no_std` VM, injects it into a new
executable segment, patches the original function to jump into it, and destroys
the original function body.

The project is a production-grade prototype, not a claim of mathematical
unbreakability. The full engineering plan is [`PLAN.md`](PLAN.md), the exact
verification evidence is [`docs/VERIFICATION.md`](docs/VERIFICATION.md), known
limits are in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), and the measured
commercial/open-source positioning is in
[`docs/POSITIONING.md`](docs/POSITIONING.md).

---

## Status

| Area | Status |
|---|---|
| Linux x86-64 ELF end-to-end | **working and tested** |
| PE32+ format parse / section injection | **working; Win64 runtime Wine-tested** |
| PE/Win64 runtime execution | **working under Wine 11.20**, normal and `--constant-time`; native Windows CI staged |
| Random per-build ISA, aliases, operand orders, register maps | working |
| CFG flattening, encrypted manifest/bodies, decoys, constant blinding | working |
| Encrypted per-build decode table + fast ARX body stream | working |
| Linear + non-linear MBA (variable shifts, modular inverse) | working; GAMBA times out, SiMBA reduces |
| Shared VM for multiple protected functions | working |
| Safe Rust / no external crates | safe tier enforced; `sirus-hardened` is opt-in unsafe |
| Kani, Miri, libFuzzer, differential/tamper/bypass, Ghidra, radare2 | run locally |
| angr, KLEE, Creusot, dudect-bencher | run locally; bounded/model results stated |
| Coverage floor (85%) | **met: 86.45% tarpaulin / 87.36% llvm-cov lines** |
| Constant-time VM execution | `--constant-time` oblivious branch/loop mode below dudect threshold; normal profile leaks |
| Live memory state | virtual registers/private stack masked at rest; snapshot constant scan passes |
| Constant-time scope | private memory rejected; fixed pass budget; branches and loops supported |
| Per-call overhead (benchmark leaf function) | default ~78.6 µs / balanced ~56.6 µs / minimal ~13.5 µs; VMProtect 3.11 demo ~8.5 µs |
| Cold startup | ~0.6 ms (no packer); VMProtect demo ~2.6 s |
| Hardened tier | opt-in `--hardened`: anti-debug, RDTSC/LFENCE, Windows DR report |

---

## Hard constraints

- No external crates in shipped code.
- No `unsafe` anywhere in shipped code or generated VM source.
- No heap allocation in the compiler core or VM.
- The injected VM is `no_std`, freestanding, position-independent, and makes no
  OS/libc calls.
- Any unsupported x86 form fails the build; unsupported bytecode fails closed at
  runtime.
- `rustc` is required at protection time; it is a compiler, not a crate
  dependency.

The build-time CLI uses `std` only at the filesystem/process boundary. The
compiler core and runtime are fully `no_std`.

---

## Quick start

```sh
# Build the protector
cargo build --release -p sirus-protector

# Build a victim with Rust
rustc --edition=2021 -C opt-level=2 -C panic=abort -C debuginfo=0 \
    victim.rs -o victim

# Protect by unique symbol substring
./target/release/sirus protect \
    --input victim \
    --output victim.protected \
    --function-contains sirus_demo_check \
    --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# Execute
./victim.protected 7 3
```

Omit `--seed` to use OS entropy. Use `--function <exact-symbol>` for an exact
symbol, or `--marker-begin <hex> --marker-end <hex>` for raw byte markers.

### CLI

```text
sirus protect --input <ELF> --output <ELF> <selector> [options]
sirus inspect <ELF-or-PE>
sirus version
```

Options:

- `--seed <64-hex>` deterministic build seed
- `--profile <max|balanced|minimal>` security/performance preset
- `--fuel <n>` runtime instruction budget (default 2,000,000)
- `--mba-depth <n>` 0..=8 (default 3)
- `--mba-budget <n>` expression node budget (default 512)
- `--decoys <n>` opaque guard/decoy pairs per function (default 2)
- `--constant-time` oblivious branch/loop execution: fixed pass budget, predicated register writes, private memory rejected
- `--constant-time-passes <n>` fixed loop frontier budget (1..=4096, default 256)
- `--vm-base <hex>` VM virtual address override
- `--emit-source <path>` write generated VM source for audit
- `--keep-temp` retain compiler temporary files
- `--no-scrub` do not destroy the original function body

---

## Supported targets and code

Supported instruction subset includes common integer `mov`, `movzx`, `movsx`,
`movsxd`, `lea`, `add`, `sub`, `and`, `or`, `xor`, `cmp`, `test`, `inc`, `dec`,
`neg`, `not`, `imul`, shifts, rotates, `push`, `pop`, `leave`, `cdqe`, `jmp`,
`jcc`, `ret`, `cmovcc`, `setcc`, and stack-frame addressing.

Not virtualizable (fail closed): calls, indirect jumps, RIP-relative data,
floating point/SSE/AVX, x87, syscalls, atomics, privilege/segment instructions,
jump tables, host pointer dereference, stack arguments beyond the sixth, and
functions with cross-block flag liveness that cannot be proven.

The ABI is System V AMD64 with up to six integer arguments and one integer
result. Virtualized code operates on a private 4 KiB stack and cannot access host
memory.

---

## Verification

Fast local gate:

```sh
./scripts/verify.sh
```

It runs formatting, Clippy with `-D warnings` across all targets, all tests,
rustdoc with warnings denied, `cargo deny`, `cargo audit`, Kani proofs, and the
red-team harness.

Long proof gate:

```sh
./scripts/prove.sh
```

It runs Kani, Miri on core and VM unit tests, and a libFuzzer session. Set
`SIRUS_FULL_MIRI=1` for the full Miri execution suite (long) and
`SIRUS_COVERAGE=1` for coverage.

External evidence can be enabled individually:

```sh
SIRUS_GHIDRA=1 SIRUS_RADARE2=1 SIRUS_MBA=1 SIRUS_ANGR=1 \
SIRUS_KLEE=1 SIRUS_CREUSOT=1 SIRUS_DUDECT=1 \
SIRUS_CONSTANT_TIME=1 SIRUS_WINDOWS=1 ./scripts/prove.sh
```

The individual scripts are `scripts/ghidra-check.sh`,
`scripts/radare2-check.sh`, `scripts/mba-check.sh`, `scripts/angr-check.py`,
`scripts/klee-check.sh`, `scripts/creusot-check.sh`,
`scripts/dudect-external.sh`, `scripts/dudect-check.sh`, `scripts/constant-time-check.sh`, and `scripts/windows-wine-check.sh`. They require the
external tools listed in `scripts/install-tools.sh`; results and caveats are in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).

Current measured results and residuals are in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md) and
[`docs/RED_TEAM.md`](docs/RED_TEAM.md). Vulnerability handling is described in
[`SECURITY.md`](SECURITY.md).

---

## Hardened runtime (opt-in, unsafe)

The default safe tier still uses `forbid(unsafe_code)`. `--hardened` generates
entries that call the optional `sirus-hardened` runtime:

- Linux: raw-syscall `/proc/self/status` tracer detection
- Windows: PEB `BeingDebugged` / `NtGlobalFlag` detection
- x86-64: LFENCE-serialized RDTSC timing budget
- failure returns `0` instead of the protected value

Diagnose the current host:

```sh
./target/release/sirus harden-check
```

Prove normal output plus tracer rejection, timing failure, and LFENCE/TSC:

```sh
./scripts/hardened-check.sh
```

Windows debug-register inspection is available through `harden-check` on a
native Windows host; Linux user mode reports it as unsupported.

## Windows runtime

PE32+ Win64 runtime injection is implemented and verified under Wine with the
same encrypted VM and the same leaf-function subset, in normal and
`--constant-time` modes. See
[`docs/WINDOWS.md`](docs/WINDOWS.md) and run:

```sh
./scripts/windows-wine-check.sh
```

A native Windows CI job and `scripts/windows-native-check.sh` are staged in
`.github/workflows/windows-wine.yml`; the native job has not yet been executed.
The executed gate is the Wine path.

## Repository layout

```text
crates/sirus-core       no_std compiler, IR, lifter, MBA, ISA, cipher, encoder
crates/sirus-vm         no_std VM engine and execution tests
crates/sirus-binfmt     no_std ELF/PE parsers and safe editors
crates/sirus-protector  std CLI, VM synthesis, rustc driver, injection pipeline
bench/                   reproducible call-overhead victim and comparison
fuzz/                    cargo-fuzz harness (external verification tooling only)
verification/creusot     Creusot/Why3 boundary proof models
verification/dudect      official dudect-bencher harness
scripts/                 verify, prove, red-team, external checks, tool installation
docs/                    architecture, Windows, threat model, format, limitations, proof evidence
```

---

## Security notice

Sirus is designed for asymmetric reverse-engineering cost, not absolute
protection. An attacker with unlimited local time, instrumentation, and CPU
control can eventually recover behavior. The runtime deliberately contains no
unsafe code, which means native self-code checksumming, RDTSC timing detection,
debug-register inspection, and LFENCE-based speculative controls are not
implemented. Those gaps are documented rather than faked.

Use Sirus for license checks, protocol/key derivation, or proprietary integer
logic where deep data binding and per-build mutation matter. Do not use it to
protect secrets from an attacker who controls the machine and can instrument
arbitrary execution.
