import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# Echo around 4276C and success epi after rjoin
print("=== 427E0-42900 ===")
for i in md.disasm(pe.get_data(0x427E0, 0x120), 0x800427E0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
