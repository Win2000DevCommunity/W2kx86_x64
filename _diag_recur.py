import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 1E62C ===")
for i in md.disasm(pe.get_data(0x1E62C, 0x60), 0x8001E62C):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
print("\n=== 477CC ===")
for i in md.disasm(pe.get_data(0x477CC, 0x40), 0x800477CC):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
print("\n=== 1D574 full ===")
for i in md.disasm(pe.get_data(0x1D574, 0x50), 0x8001D574):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
print("\n=== 39880 ===")
for i in md.disasm(pe.get_data(0x39870, 0x50), 0x80039870):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# x86 equivalent of 1d574 area - search for push 0x30; push something
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# find push 30h near RaiseException or similar
# pe64 1D574 might map from x86 - look for mov edx, 0x30 pattern in x86 related to 477cc
# 477CC looks like code - maybe a string in .text?
data=pe.get_data(0x477CC, 64)
print('477CC raw', data[:64])
print('as utf16', data[:64].decode('utf-16-le','replace'))
