#!/usr/bin/env python3
"""Manually parse w2kshim64 export table."""
import struct
import sys

with open(sys.argv[1], 'rb') as f:
    data = f.read()

# Find PE header
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
opt_hdr_off = pe_off + 4 + 20  # PE sig + COFF header
# Optional header magic
magic = struct.unpack_from('<H', data, opt_hdr_off)[0]
if magic == 0x20B:  # PE64
    data_dir_off = opt_hdr_off + 112  # after standard fields
else:
    data_dir_off = opt_hdr_off + 96

# Export directory is data directory #0
export_rva, export_size = struct.unpack_from('<II', data, data_dir_off)

print(f"Export dir RVA=0x{export_rva:X} size={export_size}")

# Parse export directory
# Find which section contains export_rva
sect_hdr_off = data_dir_off + 128  # 16 * 8
num_sects = struct.unpack_from('<H', data, pe_off + 6)[0]
print(f"Number of sections: {num_sects}")

def rva_to_offset(rva):
    for i in range(num_sects):
        sh_off = sect_hdr_off + i * 40
        s_rva = struct.unpack_from('<I', data, sh_off + 12)[0]
        s_size = struct.unpack_from('<I', data, sh_off + 16)[0]
        s_raw = struct.unpack_from('<I', data, sh_off + 20)[0]
        if s_rva <= rva < s_rva + s_size:
            return s_raw + (rva - s_rva)
    return None

exp_off = rva_to_offset(export_rva)
if exp_off is None:
    print("Cannot find export offset")
    sys.exit(1)

# Export directory header
exp = struct.unpack_from('<IIHHIIIIIII', data, exp_off)
(flags, timestamp, major, minor, name_rva, base,
 num_funcs, num_names, func_rva, name_ptr_rva, ord_tbl_rva) = exp

print(f"Base={base} NumFuncs={num_funcs} NumNames={num_names}")
print(f"FuncTable RVA=0x{func_rva:X} NamePtrTable RVA=0x{name_ptr_rva:X} OrdTable RVA=0x{ord_tbl_rva:X}")

func_off = rva_to_offset(func_rva)
name_off = rva_to_offset(name_ptr_rva)
ord_off = rva_to_offset(ord_tbl_rva)

print("\nFunction table (by index):")
for i in range(num_funcs):
    fn_rva = struct.unpack_from('<I', data, func_off + i * 4)[0]
    # Look for matching ordinal
    ord_val = None
    name_str = ""
    for j in range(num_names):
        o = struct.unpack_from('<H', data, ord_off + j * 2)[0]
        if o == base + i:
            ord_val = o
            # Get name
            np = struct.unpack_from('<I', data, name_off + j * 4)[0]
            n_off = rva_to_offset(np)
            if n_off:
                end = data.find(b'\x00', n_off)
                name_str = data[n_off:end].decode('ascii', errors='replace')
            break
    print(f"  [{i}] ord={ord_val} RVA=0x{fn_rva:04X} name={name_str}")
