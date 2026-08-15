import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# find WaitForSingleObject call - IAT 0x1170 -> VA 4ad01170
# FF 15 70 11 d0 4a
sig=bytes.fromhex('ff157011d04a')
text=x86.get_memory_mapped_image()
idx=0
while True:
  i=text.find(sig, idx)
  if i<0: break
  print(f'\n=== call WFS at {i:04X} ===')
  for ins in md32.disasm(text[i-20:i+8], i-20):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
  idx=i+1
