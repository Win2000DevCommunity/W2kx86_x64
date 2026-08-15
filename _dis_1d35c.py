import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 1D35C long ===")
for i in md.disasm(pe.get_data(0x1D35C, 0x1C0), 0x8001D35C):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address > 0x8001D500:
        break
