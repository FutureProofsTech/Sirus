# Windows PE32+ / Win64 Runtime

**Status:** Linux-hosted Wine-tested prototype; native Windows CI is staged in
`.github/workflows/windows-wine.yml` and has not yet been run on a Windows host.

---

## 1. What works now

- PE32+ AMD64 parsing and validation.
- COFF symbol-table lookup by exact name or substring.
- Raw marker ranges converted to RVAs.
- x86-64 subset lifting from the PE image.
- The same encrypted VM payload builder used by the ELF path.
- Win64 code generation and linking:
  - `rustc --target x86_64-pc-windows-gnu`
  - `lld-link` with no imports, `/opt:noref`, and a no-op `___chkstk_ms` shim
  - extraction of `.text` and `.rdata` into one RX section; Windows-only builds
    omit function-pointer keep-statements so the extracted bytes stay
    relocation-free
- Section append, SizeOfImage/checksum update, and one E9 RVA patch per
  protected function.
- Original body bytes are overwritten with keyed junk when scrubbing is enabled
  (the default); `--no-scrub` is available for debugging.
- Base-relocation guard: the extracted `.text`/`.rdata` bytes are rejected if
  the linker records a relocation that targets them.
- Win64 argument mapping:
  - host `RCX/RDX/R8/R9` -> virtual `RCX/RDX/R8/R9`
  - the VM's internal System V argument array is reordered at the generated
    entry thunk.
- Wine execution of the protected PE32+ binary.

Verified locally:

```sh
./scripts/windows-wine-check.sh
```

```text
PASS Windows/Wine PE32+ runtime
protected 2 function(s); ... VM 0x49e000; VM segment 52736 bytes; ...
```

The same victim's branch and loop outputs match the native PE under Wine.

---

## 2. ABI and supported subset

The Windows runtime follows the same strict leaf-function subset as the Linux
runtime:

- up to four integer arguments in `RCX`, `RDX`, `R8`, `R9`;
- no stack arguments;
- one integer result in `RAX`;
- conditional branches and loops inside the lifted function are supported;
- no calls, indirect control flow, SSE/AVX/x87, RIP-relative data, or host
  pointer dereference;
- no exception/unwind metadata in the injected VM;
- no Windows CFG guard-table integration.

The stack-probe symbol is a local no-op shim because the freestanding VM uses a
small fixed stack and does not call Windows libraries. This is part of the
prototype boundary.

---

## 3. Wine and CI

Wine 11.20 is the local execution environment. The gate requires:

```sh
rustup target add x86_64-pc-windows-gnu
# mingw-w64 toolchain, lld-link, wine
```

The GitHub workflow installs Wine, mingw-w64, and lld on Ubuntu and runs the same
script. It is staged, not claimed as an executed Windows-host gate.

---

## 4. What is still not claimed

- Native Windows loader/CFG/exception compatibility validation.
- Windows anti-debug/anti-tamper behavior.
- Production signing, resources, DLL exports, TLS callbacks, and imports.
- Full x86-64 or ARM64 Windows instruction coverage.

These are separate-version work; the Linux ELF product remains the primary
production path.
