import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# find function start before 1C65C
print("=== 1C580-1C660 ===")
for i in md.disasm(pe.get_data(0x1C580, 0xE0), 0x8001C580):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("\n=== x86 EE80-EF70 ===")
for i in md32.disasm(x86.get_data(0xEE80, 0x100), 0xEE80):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
