import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# find setjmp on 5bb40
text=pe.sections[0].get_data(); base=0x1000
import struct
pat=struct.pack('<Q', 0x8005bb40)
off=0
hits=[]
while True:
  i=text.find(pat, off)
  if i<0: break
  hits.append(base+i); off=i+1
print('5bb40 refs', [hex(h) for h in hits[:20]])
for h in hits[:8]:
  print(f'\n=== {h:06X} ===')
  for i in md.disasm(pe.get_data(max(0x1000,h-8), 0x30), 0x80000000+max(0x1000,h-8)):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address > 0x80000000+h+0x18: break
