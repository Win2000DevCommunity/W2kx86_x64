import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 14974 full-ish ===")
for i in md.disasm(pe.get_data(0x14974, 0x200), 0x80014974):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address - 0x80000000 > 0x14B50:
        break
print("\n=== 14E1D (jne nonzero setjmp) ===")
for i in md.disasm(pe.get_data(0x14E1D, 0x40), 0x80014E1D):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
print("\n=== 45800 caller ===")
for i in md.disasm(pe.get_data(0x457E0, 0xA0), 0x800457E0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
