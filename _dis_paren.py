import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 458B0-45980 ===")
for i in md.disasm(pe.get_data(0x458B0, 0xE0), 0x800458B0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 F7AA-F830 ===")
for i in md32.disasm(x86.get_data(0xF7AA, 0x90), 0xF7AA):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
