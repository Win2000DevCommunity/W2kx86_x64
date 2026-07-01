#!/usr/bin/env python3
"""Repair 0x90D0 prompt cave overlap with drive-letter jmp target 0x90E9."""
from __future__ import annotations

import os
import struct
import sys

import pefile

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(ROOT, "build_out4", "cmd_shim_fixed.exe")


def repair(path: str) -> int:
    pe = pefile.PE(path)
    img = bytearray(pe.get_memory_mapped_image())
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    text_rva = text.VirtualAddress

    def off(rva: int) -> int:
        return rva - text_rva

    # Find nop cave (skip 0x8000-0x9200).
    need = 40
    cave_rva = None
    lo = max(0, 0x8000 - text_rva)
    run = 0
    start = 0
    for i in range(lo, len(img)):
        rva = text_rva + i
        if 0x8000 <= rva < 0x9200:
            run = 0
            continue
        if img[i] in (0x90, 0xCC):
            if run == 0:
                start = rva
            run += 1
            if run >= need:
                cave_rva = start
                break
        else:
            run = 0
    if cave_rva is None:
        print("no cave found")
        return 1

    entry_rva = 0x3D196
    orig = bytes(img[off(entry_rva) : off(entry_rva) + 8])
    cont_rva = entry_rva + 8
    stub = bytearray()
    stub += b"\x48\xba" + struct.pack("<Q", base + 0x414B0)
    call_at = cave_rva + len(stub)
    stub += b"\xe8" + struct.pack("<i", 0x2D813 - (call_at + 5))
    stub += orig
    jmp_from = cave_rva + len(stub)
    stub += b"\xe9" + struct.pack("<i", cont_rva - (jmp_from + 5))
    cave_sz = 48
    body = stub + b"\x90" * (cave_sz - len(stub))
    img[off(cave_rva) : off(cave_rva) + cave_sz] = body
    img[off(entry_rva) : off(entry_rva) + 5] = (
        b"\xe9" + struct.pack("<i", cave_rva - (entry_rva + 5))
    )
    # Clear legacy overlap and restore batch path at 0x90E9.
    img[off(0x90D0) : off(0x90E9)] = b"\x90" * (0x90E9 - 0x90D0)
    img[off(0x90E9) : off(0x90E9) + 3] = b"\x48\x89\xda"  # mov rdx, rbx
    img[off(0x90F9) : off(0x90F9) + 5] = b"\x31\xc0" + b"\x90" * 3
    # skip batch path 0x90EF-0x9111
    jmp_rel = 0x9111 - (0x9111 - 5 + 5)
    stub_end = 0x9111
    jmp_off = stub_end - 5
    jmp_rel = 0x9111 - (jmp_off + 5)
    patch = b"\x31\xc0" + b"\x90" * (jmp_off - off(0x90EF) - 2) + b"\xe9" + struct.pack("<i", jmp_rel)
    img[off(0x90EF) : off(0x9111)] = patch

    # Write back to file raw offsets
    raw = bytearray(open(path, "rb").read())
    for rva in range(text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize):
        fo = pe.get_offset_from_rva(rva)
        if fo is None:
            continue
        raw[fo] = img[rva]

    out_path = path.replace(".exe", "_repaired.exe") if path.endswith(".exe") else path + ".repaired"
    open(out_path, "wb").write(raw)
    print(f"repaired -> {out_path}")
    print(f"  prompt cave @ 0x{cave_rva:X}")
    print(f"  0x90E9: {img[off(0x90E9):off(0x90E9)+3].hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(repair(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
