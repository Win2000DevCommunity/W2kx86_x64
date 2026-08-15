import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_probe_bp.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 1EA3C ===")
for i in md.disasm(pe.get_data(0x1EA3C, 0x80), 0x8001EA3C):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
print("\n=== 14974 ===")
for i in md.disasm(pe.get_data(0x14974, 0x40), 0x80014974):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
# who calls 45800 area - find function start
print("\n=== 457C0-45820 ===")
for i in md.disasm(pe.get_data(0x457C0, 0x80), 0x800457C0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
