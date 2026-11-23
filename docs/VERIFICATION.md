# Verification Record

**Host:** Linux x86-64, Fedora-class environment  
**Stable toolchain:** rustc 1.99.0 (2026-09-28)  
**Nightly toolchain:** 2026-08-03 / 2026-08-21 family for Miri and fuzzing  
**Kani:** 0.68.0  
**Project state:** all features described in `README.md` implemented and tested  
**Last evidenced run:** current working tree before final documentation commit

This file records commands actually executed. Anything not executed is listed as
an open gap, not inferred.

---

## 1. Fast gate

```sh
./scripts/verify.sh
```

Result: **exit 0**. The script runs:

- `cargo fmt --all -- --check` — pass
- `cargo clippy --workspace --all-targets -- -D warnings` — pass
- `cargo test --workspace` — pass
- `cargo deny check` — pass
- `cargo audit` — pass
- `cargo kani -p sirus-core` — pass
- `cargo kani -p sirus-vm` — pass
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` — pass
- dependency tree inspection — only path crates
- forbidden unsafe-construct scan — clean
- `./scripts/red-team.sh` — pass

---

## 2. Test inventory

`cargo nextest run --workspace`:

```text
Summary [0.590s] 145 tests run: 145 passed, 0 skipped
```

Breakdown:

| Target | Tests |
|---|---:|
| `sirus-binfmt` unit tests | 14 |
| `sirus-binfmt` real-loader test | 1 |
| `sirus-core` unit tests | 74 |
| `sirus-protector` unit tests | 19 |
| `sirus-protector` end-to-end | 1 |
| `sirus-protector` pipeline errors | 1 |
| `sirus-protector` marker end-to-end | 1 |
| `sirus-vm` unit tests | 8 |
| `sirus-vm` execution | 15 |
| `sirus-vm` deterministic fuzz | 2 |
| `sirus-vm` malformed payloads | 9 |

The end-to-end tests compile a real victim, protect it, compare outputs, check
body scrubbing, compare two seeds, tamper payload, forced-return bypass, and run
the real protected binary.

### Release profile build

```sh
cargo build --release --workspace
```

Result: exit 0; `target/release/sirus` is a stripped 593 KiB PIE with the
documented release profile. A real victim protected with the release binary
matched native output for the branch/loop sample.

---

## 3. Kani

```sh
cargo kani -p sirus-core
cargo kani -p sirus-vm
```

Results:

- `sirus-core`: **5 / 5 harnesses verified**, 0 failures.
  - `manifest_size_is_total`
  - `bounded_push_is_total`
  - `read_unsigned_is_bounded`
  - `read_signed_is_bounded`
  - `sign_extend_is_total`
- `sirus-vm`: **2 / 2 harnesses verified**, 0 failures.
  - `load_memory_is_bounded`
  - `store_memory_is_bounded`

A full symbolic decoder harness was attempted and rejected as too large for CBMC
on this host. The decoder is instead covered by an opcode/error test corpus and
libFuzzer/Miri. This is recorded as a proof-scope limitation, not a pass.

---

## 4. Miri

Toolchain: `cargo +nightly miri` (miri 0.1.0, 2026-08-03).

Recorded passes:

```text
cargo +nightly miri test -p sirus-core
  46 tests passed (328.90 s)

cargo +nightly miri test -p sirus-vm --lib
  8 tests passed

cargo +nightly miri test -p sirus-vm --test execution
  11 tests passed (2051.87 s)
```

After the memory-helper slice refactor and the expanded test corpus, a final Miri
rerun is executed via `scripts/prove.sh`; its result is appended when complete.
Miri is extremely slow and is not part of the fast gate.

---

## 5. libFuzzer

```sh
cd fuzz
cargo +nightly fuzz run vm -- -max_total_time=20 -rss_limit_mb=4096 -timeout=5
```

Result:

```text
Done 66962 runs in 21 second(s)
```

No crash, panic, OOB, or timeout. The fuzz target builds a valid integrity key
for arbitrary payloads so the decoder body path is exercised, not only the
integrity rejection path.

In-tree deterministic fuzz additionally runs 20,000 random payloads and 10,000
mutations of a valid payload.

---

## 6. Coverage

```sh
cargo tarpaulin --workspace --all-targets --engine Llvm \
  --out Xml --out Lcov --output-dir target/coverage-all --timeout 120
```

Result: **87.64% line coverage (4814 / 5493 lines)**.

Per file at that run:

```text
sirus-binfmt/src/elf.rs       666/781
sirus-binfmt/src/lib.rs        56/66
sirus-binfmt/src/pe.rs        286/317
sirus-core/src/decode.rs      718/779
sirus-core/src/encode.rs      360/380
sirus-core/src/error.rs         3/52  (coverage mapping anomaly; tests execute Display)
sirus-core/src/ir.rs          166/189
sirus-core/src/lifter.rs      531/671
sirus-core/src/mba.rs         225/233
sirus-core/src/program.rs     423/450
sirus-core/src/shared/chacha.rs 111/111
sirus-core/src/shared/cipher.rs  62/63
sirus-core/src/shared/derive.rs 151/154
sirus-core/src/shared/format.rs  19/24
sirus-core/src/shared/sip.rs     68/68
sirus-protector/src/cli.rs    132/141
sirus-protector/src/entropy.rs 84/114
sirus-protector/src/error.rs   21/27
sirus-protector/src/main.rs    25/25
sirus-protector/src/pipeline.rs 183/255
sirus-protector/src/vmgen.rs   212/236
sirus-vm/src/engine.rs        312/357
```

The 100% target is **not met**. `scripts/prove.sh` enforces an 85% regression floor with `--fail-under 85`; 100% remains the release target. Uncovered lines are predominantly defensive error
returns, malformed-binary branches, and CLI/pipeline I/O failures. The exact LCOV
report is generated under `target/coverage-all/`.

---

## 7. Red-team harness

```sh
./scripts/red-team.sh
```

Actual output:

```text
PASS patch/scrub sirus_demo_check: changed=43/43
PASS patch/scrub sirus_demo_loop: changed=138/139
PASS payload entropy: shannon=7.990 min=7.589 distinct=256
PASS no obvious strings in injected segment
PASS differential payload: equal-byte ratio=0.0036 sizes=16555/15344
PASS tamper and bypass observably alter results
PASS valgrind
== red-team gates passed ==
```

Additional measured facts:

- full `.sirus` segment equal-byte ratio between the two seeds: **0.2517**;
- protected binary preserves native output for branch/loop/overflow cases;
- original function bodies are gone after the jump;
- payload tamper yields deterministic wrong output without crash/hang;
- forced-return bypass changes output;
- valgrind reports no runtime memory errors on the protected sample;
- live memory dump: original protected body absent, plaintext `.sirus` body not
  cached, but a repeatedly used sensitive constant was observed transiently in
  VM register state (`scripts/memory-dump.sh`; residual, not a full pass).

---

## 8. Dependency and policy gates

```text
cargo audit           -> 0 vulnerabilities, 4 path crate dependencies
cargo deny check      -> advisories ok, bans ok, licenses ok, sources ok
cargo tree            -> only workspace path crates, no external runtime crates
```

`fuzz/` is excluded from the workspace and uses libFuzzer only as external
verification tooling. It is not linked into shipped crates.

---

## 9. Assembly inspection

`cargo-show-asm 0.2.65` is installed. Assembly was inspected with it and with
`objdump`/`readelf` during VM development. The blob validator additionally
rejects undefined symbols, relocations, and writable load segments, which catches
libc/PLT contamination before injection.

Example:

```sh
cargo asm -p sirus-core --lib finish
cargo asm -p sirus-core --lib 1
```

---

## 10. Open gaps

| Gap | Status |
|---|---|
| 100% line/branch coverage | open; measured 87.64% lines |
| Ghidra / IDA / Binary Ninja headless validation | tools not installed |
| GAMBA / SiMBA / MBA-Blast | tools not installed |
| angr / KLEE / Triton symbolic run | not installed/run |
| live process memory dump scan | not automated |
| Creusot / AORAI | not installed/run |
| Ferrocene certified compiler | not installed |
| dudect-style timing study | not implemented |
| Windows PE runtime execution | not supported |
| handler-layout full mutation | partial; `.sirus` equality 25.2% |
| native self-code checksum / debug detection / LFENCE | impossible under safe-Rust-only |

These are not silently waived. They are release blockers for any claim of full
compliance with the supplied red-team/code-standard documents.
