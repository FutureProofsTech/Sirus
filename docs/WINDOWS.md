# Windows PE32+ / Win64 Runtime

**Status:** Wine-tested and native Windows CI-tested. All three jobs in
`.github/workflows/windows-wine.yml` pass: `pe32-wine`, `pe32-native`, and
`pe32-msvc-cfg`.

---

## 1. What works now

- PE32+ AMD64 parsing and validation.
- COFF symbol-table lookup by exact name or substring.
- Explicit `--range <hex-rva>:<hex-size>` targeting for binaries without usable
  COFF function symbols.
- DLL export protection: an exported leaf is patched through the export RVA and
  loaded by a host with `LoadLibrary`/`GetProcAddress`.
- TLS callbacks and resources survive injection; the fixture runs a TLS callback
  and loads an `RCDATA` resource after protection.
- MSVC CFG fixture targeting via PDB `S_GPROC32` sizes plus linker-map RVAs.
- x86-64 subset lifting from the PE image.
- The same encrypted VM payload builder used by the ELF path.
- Win64 code generation and linking:
  - `rustc --target x86_64-pc-windows-gnu`
  - `lld-link` with no imports, `/opt:noref`, and a guard-page-safe
    `___chkstk_ms` stack probe
  - extraction of `.text` and `.rdata` into one RX section; Windows-only builds
    omit function-pointer keep-statements so the extracted bytes stay
    relocation-free
- Section append, SizeOfImage/checksum update, and one E9 RVA patch per
  protected function.
- Original body bytes are overwritten with keyed junk when scrubbing is enabled
  (the default); `--no-scrub` is available for debugging.
- Base-relocation guard: the extracted `.text`/`.rdata` bytes are rejected if
  the linker records a relocation that targets them.
- Win64 argument mapping and an assembly ABI shim that preserves volatile GPRs
  and `XMM0`–`XMM5`. `XMM6`–`XMM15` preservation is covered by a live ABI test.
- Linked `.pdata` entries are rebased into the appended `.sirus` section, the
  ABI shims carry `.seh_proc` unwind directives, and the target exception
  directory is merged and its checksum refreshed. Unwind records with exception
  handlers or chained info are rejected until their RVAs are rebased.
- Stack arguments 5-10 are carried through the shim and execute in normal and
  constant-time modes; a Wine fixture covers an 8-argument leaf.
- Direct `call rel32` between two selected protected functions executes through
  the guest call stack; constant-time calls fail closed.
- RIP-relative read-only data and the documented SSE2 subset work on Win64.
- The fixture resolves the patched entry's `RUNTIME_FUNCTION` through
  `RtlLookupFunctionEntry` at runtime in normal and protected binaries.
- Hardened Windows builds verify the linked `.text` hash on every entry, with
  the expected value and per-entry offset patched into `.rdata` after linking.
- Wine execution of the protected PE32+ binary in normal, constant-time, and
  hardened modes.

Verified locally:

```sh
./scripts/windows-wine-check.sh
```

```text
PASS Windows/Wine PE32+ runtime (normal + constant-time + hardened)
PASS Windows/Wine C ABI matrix (XMM6-15, indirect, large frame)
PASS Windows/Wine stack arguments (5th-8th, normal + constant-time)
PASS Windows/Wine direct protected calls (normal; constant-time rejected)
PASS Windows/Wine hardened self-code checksum
```

The C ABI matrix covers direct and indirect callers, a 32 KiB stack-probed
caller, and an assembly checker that detects any clobber of `XMM6`–`XMM15`.
The same fixture runs in the native Windows and MSVC `/guard:cf` jobs.

---

## 2. ABI and supported subset

The Windows runtime follows the same strict leaf-function subset as the Linux
runtime:

- up to four integer register arguments in `RCX`, `RDX`, `R8`, `R9`, plus up
  to six stack arguments (5th-10th);
- one integer result in `RAX`;
- conditional branches and loops inside the lifted function are supported;
- RIP-relative reads of read-only data, the documented SSE2 integer subset,
  VEX-encoded 128-bit AVX integer forms, and repeated string moves/fills are
  supported;
- direct calls to another function selected in the same protection run are
  supported; `--follow-calls` auto-lifts direct local callees; external calls,
  indirect control flow, 256-bit AVX/x87, writable RIP-relative globals, and
  host pointer dereference are rejected;
- exception/unwind metadata is emitted for the injected VM and the ABI shims;
- MSVC CFG-enabled callers and indirect calls are tested. Protected entries are
  reached through a direct `rel32` jump, which CFG does not instrument; an
  indirect caller validates the original function address, which remains in the
  guard table. The injected VM does not need its own CFG guard-table entries.

The stack-probe symbol is a real probe-only x64 helper. It walks downward one
page at a time from the current stack pointer to the new frame base, touching
the guard page before lower uncommitted pages. It does not adjust `RSP` before
LLVM's own subtraction and does not call Windows libraries.

---

## 3. Execution gates

Wine 11.20 is the local execution environment. The gate requires:

```sh
rustup target add x86_64-pc-windows-gnu
# mingw-w64 toolchain, lld-link, wine
```

Native Windows host:

```sh
./scripts/windows-native-check.sh
```

The GitHub workflow has three jobs:

- Ubuntu + Wine + mingw-w64 (`scripts/windows-wine-check.sh`);
- `windows-latest` native mingw-w64/lld (`scripts/windows-native-check.sh`);
- `windows-latest` MSVC `/guard:cf` with PDB/map range extraction.

All three jobs execute the protected fixture and compare it byte-for-byte with
the native output. The CFG job also exercises the indirect caller path under
`/GUARD:CF`.

---

## 4. What is still not claimed

- Windows anti-debug/anti-tamper beyond the existing PEB/debug-register reports.
- Runtime exception propagation through a protected leaf: protected calls are
  guest-state transitions, not native unwind frames, so a language exception
  cannot unwind through them. The fixture validates the patched entry's
  runtime-function lookup instead.
- Unwind records with exception handlers or chained info; these fail closed.
- Production signing and full import/TLS edge-case coverage beyond the fixtures.
- Full x86-64 or ARM64 Windows instruction coverage.

These are separate-version work; the Linux ELF product remains the primary
production path.
