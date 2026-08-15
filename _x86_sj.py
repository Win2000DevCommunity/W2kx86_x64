import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# setjmp IAT 0x1264 -> VA 4ad01264
# FF 15 64 12 D0 4A
sig=bytes.fromhex('ff156412d04a')
text=x86.get_memory_mapped_image()
idx=0
while True:
  i=text.find(sig, idx)
  if i<0: break
  print(f'\n=== setjmp at {i:04X} ===')
  for ins in md32.disasm(text[i-30:i+6], i-30):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
  idx=i+1
# also second longjmp at 1284
sig2=bytes.fromhex('ff158412d04a')
idx=0
while True:
  i=text.find(sig2, idx)
  if i<0: break
  print(f'\n=== longjmp@1284 at {i:04X} ===')
  for ins in md32.disasm(text[i-20:i+6], i-20):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
  idx=i+1
