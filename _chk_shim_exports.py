#!/usr/bin/env python3
"""Check w2kshim64 export ordinals and function addresses."""
import pefile
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE(sys.argv[1])
pe.parse_data_directories(directories=[0])  # Parse exports

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("Shim exports (sorted by ordinal):")
for exp in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=lambda e: e.ordinal):
    name = exp.name.decode() if exp.name else '(ordinal)'
    rva = exp.address - pe.OPTIONAL_HEADER.ImageBase
    print(f"  ord={exp.ordinal:3d} RVA=0x{rva:04X} name={name}")
