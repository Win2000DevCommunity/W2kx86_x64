#!/usr/bin/env python3
"""Dump raw export ordinal table from shim DLL."""
import struct, sys

with open(sys.argv[1], 'rb') as f:
    data = f.read()

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
opt_magic_off = pe_off + 4 + 20  # PE sig + COFF
magic = struct.unpack_from('<H', data, opt_magic_off)[0]
data_dir_off = opt_magic_off + (112 if magic == 0x20B else 96)
export_rva, export_size = struct.unpack_from('<II', data, data_dir_off)

def rva_to_offset(rva):
    num_sects = struct.unpack_from('<H', data, pe_off + 6)[0]
    sect_hdr_off = data_dir_off + 128
    for i in range(num_sects):
        sh_off = sect_hdr_off + i * 40
        s_rva = struct.unpack_from('<I', data, sh_off + 12)[0]
        s_size = struct.unpack_from('<I', data, sh_off + 16)[0]
        s_raw = struct.unpack_from('<I', data, sh_off + 20)[0]
        if s_rva <= rva < s_rva + s_size:
            return s_raw + (rva - s_rva)
    return None

exp_off = rva_to_offset(export_rva)
exp = struct.unpack_from('<IIHHIIIIIII', data, exp_off)
(base, num_funcs, num_names, func_rva, name_ptr_rva, ord_tbl_rva) = (
    exp[5], exp[6], exp[7], exp[8], exp[9], exp[10])

name_off = rva_to_offset(name_ptr_rva)
ord_off = rva_to_offset(ord_tbl_rva)
func_off = rva_to_offset(func_rva)

# Read names in the order they appear in the name pointer table (which should be sorted)
print("Export Name Pointer Table (must be sorted ascending):")
names_in_order = []
for j in range(num_names):
    np = struct.unpack_from('<I', data, name_off + j * 4)[0]
    n_off = rva_to_offset(np)
    end = data.find(b'\x00', n_off)
    name_str = data[n_off:end].decode('ascii', errors='replace')
    ord_val = struct.unpack_from('<H', data, ord_off + j * 2)[0]
    fn_rva = struct.unpack_from('<I', data, func_off + (ord_val - base) * 4)[0]
    names_in_order.append((name_str, ord_val, fn_rva))
    print(f"  [{j:2d}] name={name_str:35s} ord={ord_val:2d} fnRVA=0x{fn_rva:04X}")

# Verify sorting
print()
sorted_ok = all(names_in_order[i][0] <= names_in_order[i+1][0] for i in range(len(names_in_order)-1))
print(f"Sort order valid (strcmp): {sorted_ok}")
if not sorted_ok:
    for i in range(len(names_in_order)-1):
        if names_in_order[i][0] > names_in_order[i+1][0]:
            print(f"  MISORDER at [{i}]: {names_in_order[i][0]} > {names_in_order[i+1][0]}")

# Now check: if loader uses hint=0, it checks name[0] = DllMain? No, name[0] should be first sorted name
# The hint is index into the name pointer table (sorted)
print(f"\nHint 0 points to: '{names_in_order[0][0]}' (ord={names_in_order[0][1]})")

# Find __p__fmode in the sorted list
for i, (n, o, r) in enumerate(names_in_order):
    if n == '__p__fmode':
        print(f"__p__fmode at sorted pos {i}: ord={o} fnRVA=0x{r:04X}")
    if n == 'towupper':
        print(f"towupper at sorted pos {i}: ord={o} fnRVA=0x{r:04X}")
