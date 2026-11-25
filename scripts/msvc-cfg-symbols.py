#!/usr/bin/env python3
"""Resolve exact MSVC function ranges for the CFG fixture.

The linker map supplies the final RVA. Exact code sizes come from the PDB
(`llvm-pdbutil dump --symbols`), because current MSVC COFF objects omit the
function auxiliary size records. COFF auxiliary sizes remain a fallback for
toolchains that still emit them.
"""

import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

NAMES = {"sirus_win_check", "sirus_win_mix"}


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def coff_name(data, entry, strings, string_size):
    first = u32(data, entry)
    if first == 0:
        offset = u32(data, entry + 4)
        if offset < 4 or offset >= string_size:
            return ""
        raw = data[strings + offset : strings + string_size]
    else:
        raw = data[entry : entry + 8]
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def object_sizes(path):
    """Read function sizes from COFF auxiliary records, if present."""
    data = Path(path).read_bytes()
    symbol_table = u32(data, 8)
    symbol_count = u32(data, 12)
    strings = symbol_table + symbol_count * 18
    string_size = u32(data, strings)
    sizes = {}
    index = 0
    while index < symbol_count:
        entry = symbol_table + index * 18
        name = coff_name(data, entry, strings, string_size).lstrip("_")
        aux = data[entry + 17]
        if name in NAMES and aux >= 1:
            sizes[name] = u32(data, entry + 18 + 4)
        index += 1 + aux
    return sizes


def pdb_tool():
    """Locate llvm-pdbutil on Linux or a Visual Studio Windows runner."""
    found = shutil.which("llvm-pdbutil")
    if found:
        return found
    candidates = [
        Path(vc) / "Tools" / "Llvm" / "x64" / "bin" / "llvm-pdbutil.exe"
        for vc in (
            __import__("os").environ.get("VCToolsInstallDir", ""),
            __import__("os").environ.get("VCINSTALLDIR", ""),
        )
        if vc
    ]
    candidates.extend(
        [
            Path(r"C:\Program Files\LLVM\bin\llvm-pdbutil.exe"),
            Path(r"C:\msys64\mingw64\bin\llvm-pdbutil.exe"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def pdb_sizes(path):
    """Parse S_GPROC32/S_GPROC32_ID code sizes from llvm-pdbutil output."""
    if not path or not Path(path).is_file():
        print(f"pdb not found: {path}", file=sys.stderr)
        return {}
    tool = pdb_tool()
    if tool is None:
        print("llvm-pdbutil not found", file=sys.stderr)
        return {}
    result = subprocess.run(
        [tool, "dump", "--symbols", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"llvm-pdbutil failed: {result.stderr.strip()}", file=sys.stderr)
        return {}
    sizes = {}
    current = None
    for line in result.stdout.splitlines():
        match = re.search(r"S_[GL]PROC32(?:_ID)?\b.*`([^`]+)`", line)
        if match:
            current = match.group(1).lstrip("_")
            continue
        if current is None:
            continue
        match = re.search(r"\bcode size = (\d+)\b", line)
        if match:
            if current in NAMES:
                sizes[current] = int(match.group(1))
            current = None
    if not sizes:
        print(
            f"no matching PDB procedures in {path}; "
            f"first output: {result.stdout[:400]!r}",
            file=sys.stderr,
        )
    return sizes


def map_rvas(path):
    text = Path(path).read_text(errors="replace")
    base_match = re.search(r"Preferred load address is\s+([0-9A-Fa-f]+)", text)
    if not base_match:
        raise SystemExit("map preferred load address missing")
    base = int(base_match.group(1), 16)
    rvas = {}
    for line in text.splitlines():
        for name in NAMES:
            if not re.search(rf"\b_?{re.escape(name)}\b", line):
                continue
            values = re.findall(r"\b([0-9A-Fa-f]{16})\b", line)
            for value in values:
                address = int(value, 16)
                if address >= base:
                    rvas[name] = address - base
                    break
    return rvas


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit(
            "usage: msvc-cfg-symbols.py <object> <map> [pdb]"
        )
    pdb = sys.argv[3] if len(sys.argv) == 4 else None
    sizes = pdb_sizes(pdb)
    if len(sizes) != len(NAMES):
        for name, size in object_sizes(sys.argv[1]).items():
            sizes.setdefault(name, size)
    rvas = map_rvas(sys.argv[2])
    for name in sorted(NAMES):
        if name not in sizes or name not in rvas:
            print(f"pdb sizes: {sizes}", file=sys.stderr)
            print(f"map rvas: {rvas}", file=sys.stderr)
            raise SystemExit(f"missing CFG symbol: {name}")
        print(f"{name}={rvas[name]:x}:{sizes[name]:x}")


if __name__ == "__main__":
    main()
