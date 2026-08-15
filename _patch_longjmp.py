#!/usr/bin/env python3
"""Diagnostic: patch shim longjmp to ret."""
import pefile, struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else 'build_univ342/w2kshim64.dll'
pe = pefile.PE(path)

# Find .text section
for s in pe.sections:
    if b'.text' in s.Name:
        text_va = s.VirtualAddress
        text_raw = s.PointerToRawData
        break

# longjmp is at RVA 0x1060 (ordinal 5)
rva = 0x1060
file_off = text_raw + (rva - text_va)

# Read current bytes
with open(path, 'r+b') as f:
    f.seek(file_off)
    current = f.read(4)
    print(f"longjmp at file offset 0x{file_off:X}: current bytes: {current.hex(' ')}")
    # Write ret (0xC3)
    f.seek(file_off)
    f.write(b'\xC3')
    print("Patched to RET")

# Verify
pe2 = pefile.PE(path)
d = pe2.get_data(rva, 4)
print(f"Verify RVA 0x{rva:X}: {d.hex(' ')}")
