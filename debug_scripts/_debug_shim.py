#!/usr/bin/env python3
"""Debug: build shim in isolation and check longjmp code."""
import pefile, struct, io
from x86x64.shim.builder import build_w2kshim64_dll

blob = build_w2kshim64_dll()
pe = pefile.PE(data=blob)

# Parse export directory manually
ed = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
exp_rva = ed.VirtualAddress
data = pe.get_data(exp_rva, 40)
fields = struct.unpack_from('<10I', data, 0)
chars, ts, maj_min, name_rva, base, num_funcs, num_names, addr_rva, name_ptr_rva, ord_rva = fields

name_data = pe.get_data(name_ptr_rva, num_names * 4)
ord_data = pe.get_data(ord_rva, num_names * 2)
addr_data = pe.get_data(addr_rva, num_funcs * 4)

for i in range(num_names):
    n_rva = struct.unpack_from('<I', name_data, i*4)[0]
    ord_idx = struct.unpack_from('<H', ord_data, i*2)[0]
    func_rva = struct.unpack_from('<I', addr_data, ord_idx*4)[0]
    name = pe.get_data(n_rva, 32).split(b'\x00')[0].decode()
    if name == 'longjmp':
        code = pe.get_data(func_rva, 20)
        print(f"longjmp: RVA=0x{func_rva:X}")
        print(f"first bytes: {code[:16].hex(' ')}")
        print(f"first byte: 0x{code[0]:02X} (expected 0x52)")
        if code[0] == 0x52:
            print("CORRECT!")
        else:
            print("WRONG - still the old broken version!")
        break
