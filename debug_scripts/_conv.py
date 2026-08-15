import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 242BC entry ===")
for i in md.disasm(pe.get_data(0x242BC, 0x80), 0x800242BC):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# x86 12c63
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 12c63 ===")
for i in md32.disasm(x86.get_data(0x12C63, 0x80), 0x12C63):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")

# IAT at 0x84390
print("\nIAT 84390:")
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.address and (i.address - pe.OPTIONAL_HEADER.ImageBase) == 0x84390:
            print(i.name, e.dll)
