# Sirus Positioning: Commercial and Open-Source Comparison

**Status:** measured positioning report, not a marketing claim  
**Sirus target:** `v1.5.1-hardened`
**Host:** Intel Core i5-14400F, 16 threads, Linux x86-64  
**Date:** 2026-11-24

This report answers two separate questions:

1. **Feature position:** what Sirus implements compared with popular protectors.
2. **Measured position:** how fast the same protected function runs under Sirus and a
   real commercial VM protector.

The security feature columns are vendor-documented capabilities unless explicitly
marked as locally measured. Vendor claims are not treated as independently
verified.

---

## 1. Measured benchmark

### Method

Source: `bench/overhead.rs`. Both binaries call the same `sirus_demo_check`
function in a loop with varying inputs and a checksum check. Sirus protects that
function by symbol. VMProtect selects the same `overhead::sirus_demo_check`
function through its Lua API and uses `CompilationType.Virtualization`.

- native and protected call overhead measured inside the process;
- 1,000 protected calls per sample, 7 samples, median reported;
- VMProtect 3.11.0 Linux demo, one function, default virtualization, project
  packing left enabled;
- Sirus 1.5.1 release protector, deterministic seed;
- same source, same inputs, matching checksums (`bb8882a0420aed20`);
- process startup measured separately (1 call, 7 samples).

### Results

| Build | Median per call | vs native | vs VMProtect | VM payload/body |
|---|---:|---:|---:|---:|
| Native (Sirus benchmark build) | **~1.2-1.4 ns** | 1× | 0.0002× | — |
| Native (VMProtect benchmark build) | **1.89 ns** | 1× | 0.0002× | — |
| VMProtect 3.11 demo, virtualization | **8.48 µs** | ~4,490× | 1× | not exposed |
| Sirus default (`depth=3, budget=512, decoys=2`) | **~78.7 µs** | ~49,800× | ~9.3× | 13,390 B payload |
| Sirus hardened | **~76.7 µs** | ~40,600× | ~9.0× | 13,390 B payload |
| Sirus constant-time | **~214 µs** | ~101,500× | ~25.2× | 13,390 B payload |
| Sirus balanced (`depth=1, budget=128, decoys=1`) | **~56.6 µs** | ~30,000× | ~6.7× | 8,396 B payload |
| Sirus minimal (`depth=0, budget=0, decoys=0`) | **~14.7 µs** | ~6,100× | ~1.7× | 1,268 B payload |

Representative startup, one call per process:

| Build | Startup median | Output size |
|---|---:|---:|
| Native | ~0.62 ms | 4,566,192 B |
| Sirus default | ~0.59 ms | +30,664 B (0.7%) |
| VMProtect demo, packed | ~2.6 s | 1,166,840 B (25% of input) |

### How to reproduce Sirus

```sh
SIRUS_BENCH_PROFILE=default  ./scripts/bench-overhead.sh
SIRUS_BENCH_PROFILE=balanced ./scripts/bench-overhead.sh
SIRUS_BENCH_PROFILE=minimal  ./scripts/bench-overhead.sh
```

VMProtect was run with its Linux demo console and this Lua selector:

```lua
function OnBeforeCompilation()
    local file = vmprotect.core():outputArchitecture()
    local map = file:mapFunctions()
    for i = 1, map:count() do
        local fn = map:item(i)
        if string.find(fn:name(), "sirus_demo_check", 1, true) then
            file:functions():addByAddress(
                fn:address(), CompilationType.Virtualization)
        end
    end
end
```

```sh
vmprotect_con native protected -sf bench/vmprotect-select.lua
```

### Reading the benchmark honestly

- Sirus default is now **about 7× slower per protected call** than VMProtect's
  virtualized function, not the ~250,000×-native result before the performance
  work.
- Sirus minimal is **about 2× slower per call** than VMProtect, but it disables
  the non-linear MBA and decoy layers. It is a latency-oriented profile, not the
  default security profile.
- Sirus has essentially **no packer startup cost**; the VM is in the loaded image.
  VMProtect's demo startup is dominated by packing/unpacking and demo checks.
- Packed output size is not directly comparable: VMProtect compresses the whole
  file, while Sirus leaves the host image in place and appends the VM.
- VMProtect is a mature commercial product with a different security surface.
  Its default VM complexity, anti-debug, and packing are not equivalent to Sirus
  default settings.
- The VMProtect result is from the **demo**; production builds may differ. It is
  still a real commercial virtualizer running the same function, not a vendor
  claim.

---

## 2. Feature position

Legend: **Y** = documented/implemented, **P** = partial/limited, **N** = not
supported. Commercial columns summarize public vendor documentation.

| Capability | Sirus 1.2 | VMProtect 3.11 | Code Virtualizer 4.0 | Themida 3.2 | Denuvo Anti-Tamper | Tigress | OLLVM | MOVfuscator |
|---|---|---|---|---|---|---|---|---|
| Selective code virtualization | Y | Y | Y | Y | Y | Y | N | N |
| Multiple VM designs in one file | N | Y | Y | Y | Y (dual VM) | Y | N | N |
| Full x86/x64 ISA virtualization | N (subset) | Y | Y | Y | Y | via C source | via LLVM | via C source |
| ARM64 virtualization | N | Y | Y | N | N | cross-compile | via LLVM | N |
| Linux ELF runtime | Y | Y | Y | N | N (Windows games) | via compiled C | Y | via compiled C |
| Windows PE runtime | P (Wine-tested leaf subset, normal + constant-time) | Y | Y | Y | Y | via compiled C | via compiled C | via compiled C |
| macOS/Mach-O | N | Y | Y | N | N | via compiled C | Y | N |
| Native mutation / metamorphism | P (MBA, decoys, constant blinding) | Y | Y | Y | Y | Y | Y | N (mov-only) |
| Control-flow flattening | Y | Y | Y | Y | Y | Y | Y | N/A |
| Packing | N | Y | N (composes with packer) | Y | Y | runtime codegen | N | N |
| Anti-debug / anti-VM | P (opt-in hardened) | Y | P | Y | Y | research transforms | N | N |
| Runtime code/memory integrity | P (payload binding; Linux hardened text hash; Windows native self-hash absent) | Y | P | Y | Y | research transforms | P | N |
| Licensing / activation | N | Y | N | Y (WinLicense) | Y (game entitlement) | N | N | N |
| Managed/.NET | N | Y | N | P | N | N | N | N |
| Safe Rust / zero unsafe in protected runtime | Y | N | N | N | N | partially (C generated) | N | N |
| Zero external runtime crates | Y | N | N | N | N | N | N | N |
| Source/audit available | Y | N | N | N | N | license/source limited | Y | Y |
| External local evidence in repository | Y | N/A | N/A | N/A | N/A | research papers | public papers | public demo |

### Sirus versus the open-source tools

- **OLLVM** is a compiler-IR obfuscator, not a virtualizer. It is broader across
  targets and easier to deploy, but it has no bytecode VM, no encrypted payload,
  and its published passes are the classic flattening/substitution/bogus-flow
  set. Sirus is more ambitious for a single protected leaf function on Linux.
- **Tigress** is the closest research peer: source-to-source C virtualization,
  multiple dispatch engines, superoperators, reentrant interpreters, anti-taint
  and anti-alias transforms, JIT/dynamic transforms. Tigress is substantially
  broader and more mature as an obfuscation research tool. Sirus is stronger on
  binary-level safe-Rust engineering, ELF injection, and reproducible local
  evidence.
- **MOVfuscator** reduces programs to `mov`; it is a spectacular research
  demonstration but not a selective production protector. Its performance and
  code-size costs are intentionally extreme.
- **VMProtect and Code Virtualizer** are commercial products with full-ISA
  virtualization, anti-debug, packing, licensing, multiple VM instances, and
  multi-platform support. Sirus is not in that product class yet.

### Sirus versus commercial protectors

Sirus is currently best described as:

> a reproducible, zero-unsafe Linux x86-64 research/prototype virtualizer with
> real external tool evidence, now within roughly one order of magnitude of
> commercial per-call VM performance, but without the platform coverage,
> anti-debug, packing, licensing, Windows runtime, or maturity of commercial
> products.

It is not a replacement for VMProtect/Themida/Denuvo on Windows software. It is
credible only for the narrow Linux leaf-function use case documented in
`README.md` and `docs/LIMITATIONS.md`.

---

## 3. Where the remaining gap is

### Performance

The optimized path now uses:

- a fast keyed ARX body stream (SipHash remains the integrity/manifest/key
  primitive);
- a derived alias-spec table, avoiding per-instruction SipHash/shuffle
  re-derivation;
- an encrypted per-build decode-table image decrypted once per call;
- a faster deterministic table expander;
- linear-time register-map inversion.

The remaining per-call cost is dominated by bytecode density and the safe
interpreter. The next useful steps are:

1. body-size reduction for the default MBA profile;
2. caching or precomputing decode tables without an unsafe global;
3. a benchmark profile that makes the security/performance trade explicit
   (`minimal` is already near VMProtect; `default` is the protected mode).

### Protection surface

The commercial gap is not mainly the VM concept. It is:

- Windows self-code checksum (Linux hardened builds have one; native Windows
  does not yet);
- anti-debug/anti-VM depth beyond the opt-in hardened tier's user-mode checks;
- packing, resource/import protection, licensing;
- full x86/x64 and ARM64 coverage;
- runtime exception propagation through protected leaves;
- independent long-term adversarial validation.

### Honest ranking

| Dimension | Sirus position |
|---|---|
| Open-source Linux VM-protector engineering | credible prototype |
| Safe-Rust/no-unsafe property | unusually strong |
| Per-call performance | within ~1.6× of commercial in minimal mode, ~9× in default mode |
| Cold-start performance | strong; no packer |
| Static/symbolic resistance evidence | unusually well documented for a prototype |
| Windows/production platform coverage | far behind commercial |
| Anti-debug/anti-tamper | far behind commercial |
| Maturity and independent audit | research-grade |

---

## 4. Sources

- VMProtect overview and manual:
  <https://vmpsoft.com/vmprotect/overview>,
  <https://vmpsoft.com/vmprotect/user-manual/>
- Code Virtualizer:
  <https://www.oreans.com/CodeVirtualizer.php>
- Themida:
  <https://www.oreans.com/Themida.php>
- Denuvo Anti-Tamper:
  <https://irdeto.com/video-games/denuvo-anti-cheat/anti-tamper>
- Tigress:
  <https://tigress.wtf/introduction.html>,
  <https://tigress.wtf/transformPage/docs/virtualize/index.html>
- Obfuscator-LLVM:
  <https://github.com/obfuscator-llvm/obfuscator/wiki/Features>
- MOVfuscator:
  <https://github.com/xoreaxeaxeax/movfuscator>

Local measured evidence remains in `docs/VERIFICATION.md` and
`docs/RED_TEAM.md`. The comparison report is intentionally separate from the
release gate because commercial tools are not reproducible CI dependencies.
