import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 1E2D0 ===")
for i in md.disasm(pe.get_data(0x1E280, 0x80), 0x8001E280):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# x86 near add9 / related - stack had 1D5E2
print("\n=== pe64 1D560 ===")
for i in md.disasm(pe.get_data(0x1D560, 0x50), 0x8001D560):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

print("\n=== pe64 39880 ===")
for i in md.disasm(pe.get_data(0x39880, 0x40), 0x80039880):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
