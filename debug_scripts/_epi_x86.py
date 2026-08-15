import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== shared epi 4891B ===")
for i in md.disasm(pe.get_data(0x48900, 0x40), 0x80048900):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
sig=bytes.fromhex('6a006a0053555657')
text=x86.sections[0].get_data(); base=0x1000
off=0
while True:
  i=text.find(sig, off)
  if i<0: break
  rva=base+i
  print(f'\nx86 {rva:04X}')
  for ins in md32.disasm(x86.get_data(rva, 0x80), rva):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")
    if ins.address>rva+0x50: break
  off=i+1
