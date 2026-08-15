import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 ff31 ===")
for i in md32.disasm(x86.get_data(0xff31, 0x40), 0xff31):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
# search for characteristic start of ff31 in pe64 - from x86 disasm
# Also search rva tips from common build patterns - look for string refs
# Try find functions that look like GetChar - often start with mov from global
text = pe.sections[0].get_data()
base = pe.sections[0].VirtualAddress
# x86 ff31 first bytes
print('x86 raw', x86.get_data(0xff31, 16).hex())
