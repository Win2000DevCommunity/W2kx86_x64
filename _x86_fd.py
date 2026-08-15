import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("=== x86 FD40-FE00 ===")
for i in md32.disasm(x86.get_data(0xFD40, 0xC0), 0xFD40):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
