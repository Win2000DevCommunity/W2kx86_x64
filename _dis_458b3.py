import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 45880-45920 ===")
for i in md.disasm(pe.get_data(0x45880, 0xA0), 0x80045880):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
print("\n=== 4581E waiter ===")
for i in md.disasm(pe.get_data(0x4581E, 0x50), 0x8004581E):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
