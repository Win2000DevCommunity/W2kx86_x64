import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md=Cs(CS_ARCH_X86,CS_MODE_32)
for site in [0x2988, 0xd31c, 0xd4ce, 0xee26]:
    print(f"\n=== x86 {site:04X} ===")
    for i in md.disasm(x86.get_data(site-0x20, 0x50), site-0x20):
        print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
        if i.address > site+0x20:
            break
