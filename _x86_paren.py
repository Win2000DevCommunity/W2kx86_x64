# x86 of the second wait after 10005
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)
# 10005 ends with wait?
print("=== x86 ~10061 ===")
for i in md.disasm(x86.get_data(0x10050, 0x50), 0x10050):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

# Also check what import is at the wait after test edi in x86 - search for WaitForSingleObject call near f81b area
print("\n=== x86 f7a0-f830 ===")
for i in md.disasm(x86.get_data(0xf7a0, 0xa0), 0xf7a0):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
