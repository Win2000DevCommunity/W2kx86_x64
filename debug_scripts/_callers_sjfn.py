import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
for h in [0x23a0, 0x6d60, 0x178c0, 0x17c00]:
  print(f'\n=== {h:06X} ===')
  for i in md.disasm(pe.get_data(h, 0x50), 0x80000000+h):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if '1c5f8' in i.op_str or i.address>0x80000000+h+0x40:
      break
