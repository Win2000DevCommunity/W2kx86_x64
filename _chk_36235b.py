import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 36235 ===")
for i in md.disasm(pe.get_data(0x36235, 0x80), 0x80036235):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret' and i.address>0x80036280:
        break

# x86 redirect parse - cmp ax,3c
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# find function with loop back after push 0; push 0 pattern - x86 e2b4 area
# search push 0; push 0; push ebx near cmp 3c
text=x86.sections[0].get_data(); base=0x1000
for off in range(len(text)-20):
  if text[off:off+4]==bytes.fromhex('6a006a00') and text[off+4] in (0x53,0x55): # push0 push0 push ebx/ebp
    # check for 3c nearby in next 0x40
    window=text[off:off+0x50]
    if bytes.fromhex('6683f83c') in window or bytes.fromhex('83f83c') in window:
      rva=base+off
      print(f'\nx86 candidate {rva:04X}')
      for i in md32.disasm(x86.get_data(rva, 0x60), rva):
        print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
        if i.address>rva+0x40: break
