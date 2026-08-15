import struct
import pefile
import sys

build = sys.argv[1] if len(sys.argv) > 1 else 'build_univ357'
pe = pefile.PE(f'{build}/cmd_pure.exe')
for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        break

print(f'{build} shim slot refs:')
for va in (0x800A4E70, 0x800A4E78, 0x800A4E80, 0x800A4E88,
           0x800A4E90, 0x800A4E98, 0x800A4EA0):
    n = td.count(struct.pack('<Q', va))
    slot = (va - 0x800A4E48) // 8
    print(f'  s{slot} (0x{va & 0xFFFFFFFF:X}): {n} refs')
