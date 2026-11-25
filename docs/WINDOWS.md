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
- Wine execution of the protected PE32+ binary in normal, constant-time, and
  hardened modes.

Verified locally:

```sh
./scripts/windows-wine-check.sh
```

```text
PASS Windows/Wine PE32+ runtime (normal + constant-time + hardened)
PASS Windows/Wine C ABI matrix (XMM6-15, indirect, large frame)
```

The C ABI matrix covers direct and indirect callers, a 32 KiB stack-probed
caller, and an assembly checker that detects any clobber of `XMM6`–`XMM15`.
The same fixture runs in the native Windows and MSVC `/guard:cf` jobs.

---

## 2. ABI and supported subset

The Windows runtime follows the same strict leaf-function subset as the Linux
runtime:

- up to four integer arguments in `RCX`, `RDX`, `R8`, `R9`;
- no stack arguments inside the protected leaf;
- one integer result in `RAX`;
- conditional branches and loops inside the lifted function are supported;
- no calls, indirect control flow, SSE/AVX/x87, RIP-relative data, or host
  pointer dereference inside the protected function;
- exception/unwind metadata is emitted for the injected VM and the ABI shims;
- MSVC CFG-enabled callers and indirect calls are tested; the injected VM does
  not add CFG guard-table entries of its own.

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

- Windows native self-code checksum (the Linux hardened tier implements one).
- Windows anti-debug/anti-tamper beyond the existing PEB/debug-register reports.
- Runtime exception propagation through a protected leaf: the lifter does not
  support calls, so no test can throw from inside the lifted function. The
  unwind metadata is structurally merged and validated with handler-free
  records.
- Production signing, resources, DLL exports, TLS callbacks, and imports.
- Full x86-64 or ARM64 Windows instruction coverage.

These are separate-version work; the Linux ELF product remains the primary
production path.
