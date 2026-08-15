#!/usr/bin/env python3
"""Post-build patcher: apply align-prologue CALL snap on the final binary.

The pipeline's align-prologue snap misses some calls due to RVA map state
differences between the snapshot and the final binary.  This script uses
the dumped RVA map (which matches the manual test behaviour) and patches
the binary *after* the build completes.

Usage:
    python patch_align_calls.py build_out166/cmd_pure.exe build_out166/rva.txt
"""
import pefile
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x86_x64

# ── Hardcoded path to the Win2000 x86 cmd.exe ──
X86_CMD = r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe'


def patch(x64_exe: str, rva_map_path: str) -> int:
    # Load x64 binary
    pe = pefile.PE(x64_exe)
    text = next(s for s in pe.sections if b'.text' in s.Name)
    blob = bytearray(text.get_data())

    # Load x86 source
    x86_pe = pefile.PE(X86_CMD)
    x86_text = next(s for s in x86_pe.sections if b'.text' in s.Name)
    x86_data = x86_text.get_data()
    x86_rva = x86_text.VirtualAddress

    # Load RVA map from dump file
    rva_map = {}
    with open(rva_map_path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                rva_map[int(parts[0], 16)] = int(parts[1], 16)

    # Apply fixes
    class D:
        _cmd_no_hacks = True
        _ALIGN_WRAP = b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'
    d = D()

    r1 = x86_x64.Win2000Translator._snap_branches_past_epilogues(d, blob)
    r2 = x86_x64.Win2000Translator._snap_calls_past_align_prologues(
        d, blob, rva_map, x86_data, x86_rva)
    print(f"Epilogue-past snaps: {r1}")
    print(f"Align-prologue snaps: {r2}")

    # Write patched blob back to the PE file
    text_offset = text.get_file_offset()
    with open(x64_exe, 'rb') as f:
        raw = bytearray(f.read())
    raw[text_offset:text_offset + len(blob)] = bytes(blob)
    with open(x64_exe, 'wb') as f:
        f.write(raw)

    # Verify
    pe2 = pefile.PE(x64_exe)
    t2 = next(s for s in pe2.sections if b'.text' in s.Name)
    b2 = t2.get_data()
    off = 0x13BD6 - t2.VirtualAddress
    cb = b2[off:off + 5]
    rel = struct.unpack_from('<i', cb, 1)[0]
    tgt = 0x13BD6 + 5 + rel
    print(f"call 0x13BD6 -> 0x{tgt:X}  {'OK' if tgt != 0x13BC9 else 'STILL BROKEN'}")

    return 0


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <cmd_pure.exe> <rva.txt>")
        sys.exit(2)
    sys.exit(patch(sys.argv[1], sys.argv[2]))
