import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 26AE0-26C00 ===")
for i in md.disasm(pe.get_data(0x26AE0, 0x120), 0x80026AE0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# x86 equivalent around 13E50-13EE8
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 13E40-13EE8 ===")
for i in md32.disasm(x86.get_data(0x13E40, 0xB0), 0x13E40):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
