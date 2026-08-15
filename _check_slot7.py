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

# Find movabs refs to slot 7 (towupper, 0x800A4E80)
pattern = struct.pack('<Q', 0x800A4E80)
pos = 0
refs = []
while True:
    idx = td.find(pattern, pos)
    if idx < 0:
        break
    if idx >= 2 and (td[idx-2] & 0xFE) == 0x48 and 0xB8 <= td[idx-1] <= 0xBF:
        refs.append(idx - 2)
    pos = idx + 1

print(f'{len(refs)} movabs refs to slot 7 (towupper):')
for r in refs[:10]:
    rva = tv + r
    # Show preceding 25 bytes + following 10 bytes
    before = bytes(td[max(0,r-25):r])
    after = bytes(td[r+10:r+25])
    # Decode preceding instructions
    insns_b = list(md.disasm(before, 0x80000000 + max(0, tv + r - 25)))
    last_ins = insns_b[-1] if insns_b else None
    insns_a = list(md.disasm(after, 0x80000000 + tv + r + 10))
    first_a = insns_a[0] if insns_a else None
    print(f'  main+0x{rva:X}: ...{last_ins.mnemonic} {last_ins.op_str} | '
          f'movabs | {first_a.mnemonic} {first_a.op_str}...')
