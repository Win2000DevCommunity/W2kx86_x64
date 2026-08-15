import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 C65B-C6D0 ===")
for i in md.disasm(x86.get_data(0xC65B, 0x80), 0x4AD0C65B):
    print(f"  {i.address:08X}: {i.bytes.hex():20s} {i.mnemonic} {i.op_str}")
