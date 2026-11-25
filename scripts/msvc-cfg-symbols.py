#!/usr/bin/env python3
"""Extract COFF function sizes and MSVC map RVAs for the CFG fixture."""

import re
import struct
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
    data = Path(path).read_bytes()
    symbol_table = u32(data, 8)
    symbol_count = u32(data, 12)
    strings = symbol_table + symbol_count * 18
    string_size = u32(data, strings)
    sizes = {}
    debug = []
    index = 0
    while index < symbol_count:
        entry = symbol_table + index * 18
        name = coff_name(data, entry, strings, string_size)
        canonical = name.lstrip("_")
        if len(debug) < 8:
            debug.append((name, data[entry + 17]))
        if canonical in NAMES:
            print(f"object debug: {name} aux={data[entry + 17]} type={u16(data, entry + 14)} section={u16(data, entry + 12)}", file=sys.stderr)
        aux = data[entry + 17]
        if canonical in NAMES and aux >= 1:
            aux_entry = entry + 18
            sizes[canonical] = u32(data, aux_entry + 4)
        index += 1 + aux
    if not sizes:
        print(f"object debug first symbols: {debug}", file=sys.stderr)
    return sizes


def image_base(path):
    data = Path(path).read_bytes()
    pe = u32(data, 0x3C)
    optional = pe + 24
    return u64(data, optional + 0x18)


def map_rvas(path):
    text = Path(path).read_text(errors="replace")
    base_match = re.search(r"Preferred load address is\s+([0-9A-Fa-f]+)", text)
    if not base_match:
        raise SystemExit("map preferred load address missing")
    base = int(base_match.group(1), 16)
    rvas = {}
    for line in text.splitlines():
        for name in NAMES:
            if name not in line and f"_{name}" not in line:
                continue
            match = re.search(r"\b([0-9A-Fa-f]{16})\b", line)
            if match:
                address = int(match.group(1), 16)
                if address >= base:
                    rvas[name] = address - base
    return rvas


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: msvc-cfg-symbols.py <object> <map>")
    sizes = object_sizes(sys.argv[1])
    rvas = map_rvas(sys.argv[2])
    for name in sorted(NAMES):
        if name not in sizes or name not in rvas:
            print(f"object sizes: {sizes}", file=sys.stderr)
            print(f"map rvas: {rvas}", file=sys.stderr)
            raise SystemExit(f"missing CFG symbol: {name}")
        print(f"{name}={rvas[name]:x}:{sizes[name]:x}")


if __name__ == "__main__":
    main()
