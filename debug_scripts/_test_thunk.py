import sys
sys.path.insert(0, '.')

# Test _ff25_iat_slot_at_rva with the actual translator PE class
import importlib
from x86x64.translator import _iat
import inspect

# Find how the translator PE class reads RVA
from x86x64.pe.image32 import PE32Image
import struct

pe = PE32Image(open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb').read())

# Read bytes at RVA 0x1A760 and 0x1A766
def read_rva(pe_obj, rva, n):
    sec = pe_obj.section_for_rva(rva)
    data = pe_obj.get_section_data(sec)
    off = rva - sec['vaddr']
    return data[off:off+n]

print('Bytes at RVA 0x1A760:', read_rva(pe, 0x1A760, 6).hex())
print('Bytes at RVA 0x1A766:', read_rva(pe, 0x1A766, 6).hex())
print('IAT slot from 0x1A760:', hex(struct.unpack_from('<I', read_rva(pe, 0x1A760, 6), 2)[0]))
print('IAT slot from 0x1A766:', hex(struct.unpack_from('<I', read_rva(pe, 0x1A766, 6), 2)[0]))

# Find the x86 E8 calls to thunk 0x1A766 and check if any resolve to 0x1A760
print()
print('x86 E8 calls near thunks 0x1A760/0x1A766:')
for sec in pe.sections:
    nm = sec['name']
    if isinstance(nm, bytes):
        nm = nm.decode()
    if nm.startswith('.text'):
        td = pe.get_section_data(sec)
        tv = sec['vaddr']
        break

i = 0
while i < len(td) - 5:
    if td[i] == 0xE8:
        rel = struct.unpack_from('<i', td, i + 1)[0]
        tgt_rva = (tv + i + 5 + rel) & 0xFFFFFFFF
        if 0x1A75E <= tgt_rva <= 0x1A768:
            print(f'  E8 at x86 RVA 0x{tv+i:X} -> thunk 0x{tgt_rva:X} '
                  f'(IAT slot from thunk: 0x{struct.unpack_from("<I", read_rva(pe, tgt_rva, 6), 2)[0]:X})')
        i += 5
    else:
        i += 1
