#!/usr/bin/env python3
"""Dump raw export name strings from shim DLL."""
import struct, sys

with open(sys.argv[1], 'rb') as f:
    data = f.read()

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
magic = struct.unpack_from('<H', data, pe_off + 4 + 20)[0]
dd = pe_off + 4 + 20 + (112 if magic == 0x20B else 96)
export_rva, _ = struct.unpack_from('<II', data, dd)

def rva2off(rva):
    ns = struct.unpack_from('<H', data, pe_off + 6)[0]
    sh = dd + 128
    for i in range(ns):
        so = sh + i * 40
        sr = struct.unpack_from('<I', data, so + 12)[0]
        ss = struct.unpack_from('<I', data, so + 16)[0]
        sf = struct.unpack_from('<I', data, so + 20)[0]
        if sr <= rva < sr + ss:
            return sf + (rva - sr)
    return None

eo = rva2off(export_rva)
exp = struct.unpack_from('<IIHHIIIIIII', data, eo)
(name_ptr_rva, ord_tbl_rva) = exp[9], exp[10]
num_names = exp[7]

no = rva2off(name_ptr_rva)
oo = rva2off(ord_tbl_rva)

print("Export names raw:")
for j in range(num_names):
    np = struct.unpack_from('<I', data, no + j * 4)[0]
    n_off = rva2off(np)
    end = data.find(b'\x00', n_off)
    raw = data[n_off:end]
    name_str = raw.decode('ascii', errors='replace')
    ord_val = struct.unpack_from('<H', data, oo + j * 2)[0]
    
    # Check for issues
    issues = []
    if name_str != raw.decode('ascii', errors='strict'):
        issues.append('NON-ASCII')
    if end - n_off != len(raw):
        issues.append('NO-NULL')
    
    print(f"  [{j:2d}] ord={ord_val:2d} raw={raw.hex():30s} name={name_str}", end='')
    if issues:
        print(f'  ISSUES: {issues}')
    else:
        print()
