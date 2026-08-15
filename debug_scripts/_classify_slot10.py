import struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE('build_univ355/cmd_pure.exe')
for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Find all movabs rax, 0x800A4E98 refs and disassemble 30 bytes after each
pattern = struct.pack('<Q', 0x800A4E98)
pos = 0
refs = []
while True:
    idx = td.find(pattern, pos)
    if idx < 0:
        break
    if idx >= 2 and (td[idx-2] & 0xFE) == 0x48 and 0xB8 <= td[idx-1] <= 0xBF:
        refs.append(idx - 2)
    pos = idx + 1

print(f'{len(refs)} movabs refs to slot 10. Classification:')
for r in refs:
    rva = tv + r
    # Disassemble from the movabs
    code = bytes(td[r:r+25])
    insns = list(md.disasm(code, 0x80000000 + rva))
    desc = []
    for ins in insns[:4]:
        desc.append(f'{ins.mnemonic} {ins.op_str}')
    after = ' | '.join(desc)
    print(f'  main+0x{rva:X}: {after}')
