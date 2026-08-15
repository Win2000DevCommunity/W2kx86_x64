import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
for h in [0x1d500, 0x1d526, 0x1d540, 0x1d566, 0x1d574, 0x1d5a6, 0x36260]:
    print(f"\n=== {h:06X} ===")
    for i in md.disasm(pe.get_data(h, 0x40), 0x80000000+h):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
        if i.address >= 0x80000000+h+0x30:
            break
