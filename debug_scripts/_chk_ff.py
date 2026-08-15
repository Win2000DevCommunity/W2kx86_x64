import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 1ea3c (ff31?) ===")
for i in md.disasm(pe.get_data(0x1ea3c, 0x50), 0x8001ea3c):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
