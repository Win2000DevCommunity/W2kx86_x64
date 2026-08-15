import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

with open('build_univ358/w2kshim64.dll', 'rb') as f:
    d = f.read()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Shim .text at RVA 0x1000, file offset 0x200
print('Shim disasm 0x1740-0x17B0:')
for ins in md.disasm(d[0x1740-0x1000+0x200:0x17B0-0x1000+0x200+16], 0x1800101740):
    print(f'  shim+0x{ins.address-0x1800100000:X}: {ins.mnemonic} {ins.op_str}')
