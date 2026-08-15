import pefile
pe = pefile.PE("build_univ257/cmd_pure.exe")
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.address:
            rva = i.address - pe.OPTIONAL_HEADER.ImageBase
            if rva in (0x84e78, 0x845f0, 0x845e0) or (i.name and b"Wait" in i.name):
                print(hex(rva), i.name, e.dll)
# also 361bf site
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== 361A0 ===")
for i in md.disasm(pe.get_data(0x361A0, 0x80), 0x800361A0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
