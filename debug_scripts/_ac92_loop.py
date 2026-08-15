import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 1089f ===")
for i in md32.disasm(x86.get_data(0x10890, 0x80), 0x10890):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
print("=== pe64 around CheckSwitches 26b40 ===")
from capstone import CS_MODE_64, CS_ARCH_X86 as A
md = Cs(A, CS_MODE_64)
pe = pefile.PE("build_univ257/cmd_pure.exe")
for i in md.disasm(pe.get_data(0x26B20, 0x90), 0x80026B20):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
# Find pe64 of SingleCommand 58F64 setters
text = pe.get_data(0x1000, 0x57000)
import struct
needle = struct.pack("<Q", 0x80058F64)
idx=0
while True:
    p=text.find(needle, idx)
    if p<0: break
    print(f"58F64 imm at {p+0x1000:#x}")
    idx=p+1
