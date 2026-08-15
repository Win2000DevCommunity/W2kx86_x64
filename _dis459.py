import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 45980-459D0 ===")
for i in md.disasm(pe.get_data(0x45980, 0x50), 0x80045980):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}  [{i.bytes.hex()}]")
print("=== 459A0 area raw ===")
print(pe.get_data(0x459A0, 0x30).hex())
