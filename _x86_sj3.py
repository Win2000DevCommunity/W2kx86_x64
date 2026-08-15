import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
text=x86.get_memory_mapped_image()
# setjmp IAT call FF 15 64 12 D0 4A
sig=bytes.fromhex('ff156412d04a')
idx=0
while True:
  i=text.find(sig, idx)
  if i<0: break
  print(f'\n=== _setjmp3 at {i:04X} ===')
  for ins in md32.disasm(text[i-24:i+6], i-24):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
  idx=i+1

for site in [0xef64, 0xf01a, 0xffed, 0x10067]:
  print(f'\n=== push fb40 site {site:04X} ===')
  for ins in md32.disasm(text[site-8:site+20], site-8):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
