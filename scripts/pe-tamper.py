#!/usr/bin/env python3
"""Flip one byte inside the injected `.sirus` section of a PE32+ image."""

import struct
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: pe-tamper.py <input.exe> <output.exe>")
    source, destination = map(Path, sys.argv[1:])
    data = bytearray(source.read_bytes())
    if data[:2] != b"MZ":
        raise SystemExit("not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise SystemExit("bad PE signature")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + optional_size
    for index in range(count):
        header = table + index * 40
        name = bytes(data[header : header + 8]).rstrip(b"\0")
        virtual_size, _virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, header + 8
        )
        if name != b".sirus":
            continue
        if raw_size <= 4 or raw_offset + raw_size > len(data):
            raise SystemExit("invalid .sirus section")
        # The first bytes are generated VM text; skip the section prefix.
        data[raw_offset + 2] ^= 1
        destination.write_bytes(data)
        print(f"tampered .sirus offset {raw_offset + 2:#x} size {virtual_size:#x}")
        return
    raise SystemExit("missing .sirus section")


if __name__ == "__main__":
    main()
