import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
print("ImageBase", hex(x86.OPTIONAL_HEADER.ImageBase))
# get raw at RVA 0x1089f
data = x86.get_data(0x1089F, 0x60)
print(data[:32].hex())
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
for i in md32.disasm(data, 0x4ad1089f):
    print(f"  {i.address:08X}: {i.mnemonic} {i.op_str}")

# pe64 58F64 writers - disasm around 13ec4 and 44168
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
for h in (0x13EA0, 0x44140, 0xCD00, 0x28A30):
    print(f"\n=== {h:#x} ===")
    for i in md.disasm(pe.get_data(h, 0x50), 0x80000000+h):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
