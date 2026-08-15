import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
text = pe.sections[0].get_data(); base = pe.sections[0].VirtualAddress
for target in [0x3624D, 0x1d35c, 0x1d4f4, 0x1e62c]:
  hits=[]
  for i in range(len(text)-5):
    if text[i]==0xE8:
      rel=struct.unpack_from('<i', text, i+1)[0]
      if i+5+rel == target-base:
        hits.append(base+i)
  print(hex(target), 'callers', [hex(h) for h in hits[:20]], 'n', len(hits))

data=pe.get_data(0x477CC, 0x40)
print('table dwords:')
for i in range(0, 0x40, 4):
  v=struct.unpack_from('<I', data, i)[0]
  print(f'  +{i:02x}: {v:08X}')

md=Cs(CS_ARCH_X86,CS_MODE_64)
print('\n=== after WFS 45855 ===')
for i in md.disasm(pe.get_data(0x45855, 0x50), 0x80045855):
  print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

print('\n=== 1D35C ===')
for i in md.disasm(pe.get_data(0x1D35C, 0x50), 0x8001D35C):
  print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
