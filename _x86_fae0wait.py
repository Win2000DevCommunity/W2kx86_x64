import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# fae0==0 then wait - search cmp [fae0],0 ; je/jne near push -1
# 83 3D E0 FA D1 4A 00
sig=bytes.fromhex('833de0fad14a00')
text=x86.get_memory_mapped_image()
idx=0
while True:
  i=text.find(sig, idx)
  if i<0: break
  print(f'\n=== cmp fae0,0 at {i:04X} ===')
  for ins in md32.disasm(text[i:i+0x40], i):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
    if ins.address > i+0x35: break
  idx=i+1
