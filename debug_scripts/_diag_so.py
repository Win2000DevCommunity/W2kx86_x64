import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe = pefile.PE("build_univ258/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 14970-14A40 (SO site) ===")
for i in md.disasm(pe.get_data(0x14970, 0xD0), 0x80014970):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

print("\n=== IAT 84ea0 ===")
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.address and (i.address - pe.OPTIONAL_HEADER.ImageBase) in (0x84ea0, 0x84e78, 0x845f0):
            print(hex(i.address - pe.OPTIONAL_HEADER.ImageBase), i.name, e.dll)

# x86 equivalent - setjmp area near Wait?
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
# find setjmp / longjmp callers
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.name and (b"setjmp" in i.name.lower() or b"longjmp" in i.name.lower()):
            print("x86", i.name, hex(i.address))
