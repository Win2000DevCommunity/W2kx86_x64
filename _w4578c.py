import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 4578C ===")
for i in md.disasm(pe.get_data(0x4578C, 0x80), 0x8004578C):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
