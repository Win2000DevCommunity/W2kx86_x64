import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# continue from 1E3D0 to find ret and any recursive calls
print("=== rest of 1E2B4 ===")
count=0
for i in md.disasm(pe.get_data(0x1E3D0, 0x250), 0x8001E3D0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic in ('call','ret','jmp') and '1d5' in i.op_str.lower():
        print('  *** INTERESTING')
    if i.mnemonic=='ret':
        count+=1
        if count>=3:
            break

# Identify IAT at 854c0
ppe=pefile.PE("build_univ258/cmd_probe_jcc.exe")
for exp in ppe.DIRECTORY_ENTRY_IMPORT:
  for imp in exp.imports:
    if imp.address and (imp.address - 0x80000000)==0x854c0:
      print('IAT 854c0', exp.dll, imp.name)

# x86 of this - search cmp bx/ax 0x3c near redirect
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# cmp ax, 0x3c = 66 83 F8 3C
text=x86.sections[0].get_data(); base=x86.sections[0].VirtualAddress
import struct
for off in range(len(text)-4):
  if text[off:off+4]==bytes.fromhex('6683f83c'):
    rva=base+off
    print(f'\nx86 cmp ax,3c at {rva:04X}')
    for i in md32.disasm(x86.get_data(rva-8, 0x40), rva-8):
      print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
      if i.address>rva+0x20: break
