import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_probe_univ.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
for base in (0x45770, 0x19A00, 0x1EA40, 0x1C650):
    print(f"\n=== {base:#x} ===")
    for i in md.disasm(pe.get_data(base, 0x60), 0x80000000+base):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
