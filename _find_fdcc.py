import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# Search for cmp word [rax], 0xa after loading c8d8 near 1E62C - fdcc signature
text=pe.sections[0].get_data(); base=0x1000
# pattern: movabs r11, 588d8; mov eax,[r11]; cmp word [rax],0xa
import struct
sig=bytes.fromhex('49bbd888058000000000')  # movabs r11, 800588d8
hits=[]
off=0
while True:
  i=text.find(sig, off)
  if i<0: break
  rva=base+i
  if 0x1E000 <= rva <= 0x1F000 or 0x45000<=rva<=0x46000:
    print(hex(rva), text[i:i+20].hex())
  hits.append(rva)
  off=i+1
print('total c8d8 loads', len(hits))

# Is fdcc body at 45894 actually wrong mapping of shared code?
print('\n=== 45894 vs expected fdcc ===')
for i in md.disasm(pe.get_data(0x45894, 0x40), 0x80045894):
  print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
