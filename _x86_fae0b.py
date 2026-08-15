import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# Use get_data with RVA
for rva in [0xF6E0, 0xF6FD, 0xF570, 0xF583, 0xF6C0]:
  print(f'\n=== {rva:04X} ===')
  try:
    for i in md32.disasm(x86.get_data(rva, 0x60), rva):
      print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
      if i.address > rva+0x40: break
  except Exception as e:
    print(e)

# Find function containing cmp fae0,4000 - scan with capstone from F6A0
print('\n=== F6A0 scan ===')
for i in md32.disasm(x86.get_data(0xF6A0, 0x100), 0xF6A0):
  print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
