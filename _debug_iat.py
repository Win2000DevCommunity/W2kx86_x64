#!/usr/bin/env python3
"""Debug: check iat_rva preservation in transform_imports."""
import sys
sys.path.insert(0, '.')
from x86x64.translator._env import *
from x86x64.dispatch.transform import transform_imports
import pefile

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
img_base = pe.OPTIONAL_HEADER.ImageBase

# Build import dicts
imports = []
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8','ignore')
    funcs = []
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else None
        funcs.append({
            'name': name,
            'ordinal': imp.ordinal,
            'hint': imp.hint,
            'iat_rva': imp.address - img_base,  # RVA
        })
    imports.append({'dll': dll, 'functions': funcs, 'iat_rva': 0, 'ilt_rva': 0})

transformed = transform_imports(imports)

# Find __p__commode (x86 IAT RVA 0x12DC) in transformed
print("Looking for __p__commode (x86 RVA 0x12DC):")
for imp in transformed:
    dll = imp['dll']
    for fn in imp['functions']:
        old_rva = fn.get('iat_rva', 0)
        ord_val = fn.get('ordinal')
        name = fn.get('name', '')
        if old_rva == 0x12DC:
            print(f"  FOUND: {dll}!{name} ord={ord_val} iat_rva=0x{old_rva:X}")
        elif ord_val == 9 and 'shim' in dll.lower():
            print(f"  SHIM ord=9: {dll}!{name} iat_rva=0x{old_rva:X}")

# Also check all shim imports
print()
print("All w2kshim64 imports:")
for imp in transformed:
    if 'shim' in imp['dll'].lower():
        for i, fn in enumerate(imp['functions']):
            ord_val = fn.get('ordinal')
            name = fn.get('name', '')
            old_rva = fn.get('iat_rva', 0)
            print(f"  [{i:2d}] ord={ord_val} name={name:30s} iat_rva=0x{old_rva:04X}")
