# Security Policy

## Supported artifact

The current release gate covers the Linux x86-64 ELF protector and generated
`no_std` VM. Win64 PE32+ runtime protection is verified under Wine for the strict
leaf subset (branches and loops included); native Windows loader/CI validation is
not yet complete.

## Reporting a vulnerability

This is a local research/prototype project. Do not deploy it as the only control
protecting high-value secrets without an independent audit. Report suspected
issues with:

- exact commit hash;
- input binary or minimal reproducer;
- protection command/seed if applicable;
- observed behavior and expected behavior;
- whether the issue is a memory-safety flaw, a protection bypass, an integrity
  failure, or a documentation/compliance gap.

## Scope

In scope:

- memory-safety or panic defects in `sirus-core`, `sirus-vm`, `sirus-binfmt`;
- malformed bytecode causing OOB, panic, hang, or fuel overrun;
- ELF/PE parser confusion or out-of-bounds read;
- protector writing a structurally invalid output or corrupting unrelated bytes;
- generated runtime importing libc or containing writable-executable segments;
- bypasses that produce valid host output from tampered payloads;
- private/secret material left in the static injected segment.

Out of scope / documented residuals:

- confidentiality against an analyst who can observe the running process; the body
  stream is obfuscation, not a cryptographic cipher/MAC (SipHash binds integrity);
- native self-code checksum evasion (not implemented);
- RDTSC/debug-register/hypervisor detection (not implemented);
- LFENCE/Spectre mitigation (not implemented);
- live memory observation of a decoded value inside one executing instruction;
  persistent VM state is masked at rest and the snapshot diagnostic passes;
- absolute resistance claims beyond the tested Ghidra/radare2/GAMBA/SiMBA/angr/KLEE
  corpus and bounded timeouts;
- constant-time execution is provided by the explicit `--constant-time` oblivious
  mode; the default branchy profile still has a measured timing leak;
- Windows execution;
- attacks requiring the ability to rewrite both payload and generated key
  shares.

See `docs/LIMITATIONS.md` and `docs/RED_TEAM.md` for the complete residual list.
