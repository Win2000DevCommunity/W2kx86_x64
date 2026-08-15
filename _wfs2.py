import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 27280-273B0 ===")
for i in md.disasm(pe.get_data(0x27280, 0x140), 0x80027280):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
# who calls 272xx function - find entry
# look for push rbp / homes before
print("\n=== func start guess ===")
for i in md.disasm(pe.get_data(0x271F0, 0xA0), 0x800271F0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
