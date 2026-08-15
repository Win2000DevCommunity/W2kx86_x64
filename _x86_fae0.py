import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# fae0 is 4ad1fae0 - search cmp [fae0], 4000h
# 81 3D e0 fa d1 4a 00 40 00 00
sig=bytes.fromhex('813de0fad14a00400000')
text=x86.get_memory_mapped_image()
idx=text.find(sig)
print('cmp fae0,4000 at', hex(idx) if idx>=0 else None)
# also 833D e0 fa d1 4a 0a = cmp dword [fae0], 0xa
sig2=bytes.fromhex('833de0fad14a0a')
idx2=text.find(sig2)
print('cmp fae0,0xa at', hex(idx2) if idx2>=0 else None)
for site in [idx, idx2]:
  if site is None or site<0: continue
  print(f'\n=== around {site:04X} ===')
  for i in md32.disasm(text[site-0x40:site+0x80], site-0x40):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
