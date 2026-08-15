import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
for h in (0x1D370, 0x1D430, 0x1D4C0, 0x1C6F0):
    print(f"\n=== {h:#x} ===")
    for i in md.disasm(pe.get_data(h, 0x60), 0x80000000+h):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
