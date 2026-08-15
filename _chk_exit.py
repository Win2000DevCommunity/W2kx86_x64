import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe = pefile.PE("build_univ257/cmd_probe_all.exe")
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.name and b"Exit" in i.name:
            print(e.dll, i.name.decode(), "iat_rva", hex(i.address - pe.OPTIONAL_HEADER.ImageBase if i.address else 0))

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 147E0-14880 ===")
for i in md.disasm(pe.get_data(0x147E0, 0xA0), 0x800147E0):
    print(f"  {i.address-0x80000000:06X}: {i.bytes.hex():28s} {i.mnemonic} {i.op_str}")

x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
for rva in [0xAC90, 0xC650, 0xC67E, 0xC6A0]:
    print("=== x86", hex(rva), "===")
    for i in md32.disasm(x86.get_data(rva, 40), 0x4AD00000 + rva):
        print(f"  {i.address:08X}: {i.mnemonic} {i.op_str}")
