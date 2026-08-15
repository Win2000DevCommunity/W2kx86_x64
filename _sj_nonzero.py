import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("=== x86 EF64-F010 ===")
for i in md32.disasm(x86.get_data(0xEF50, 0xC0), 0xEF50):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("\n=== pe64 1C675-1C720 ===")
for i in md.disasm(pe.get_data(0x1C675, 0xB0), 0x8001C675):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
