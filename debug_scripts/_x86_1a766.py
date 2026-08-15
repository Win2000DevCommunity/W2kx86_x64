import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("=== 1A766 ===")
for i in md32.disasm(x86.get_data(0x1A766, 0x40), 0x1A766):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

# FFED area more carefully  
print("\n=== FFEB ===")
for i in md32.disasm(x86.get_data(0xFFEB, 0x30), 0xFFEB):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

# 10061 area  
print("\n=== 10060 ===")
for i in md32.disasm(x86.get_data(0x10060, 0x20), 0x10060):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
