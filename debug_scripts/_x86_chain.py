import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
for rva in [0xF4EB, 0xF5A8, 0xF5BF, 0xF5D6]:
  print(f'\n=== {rva:04X} ===')
  for i in md32.disasm(x86.get_data(rva, 0x30), rva):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret':
      break
