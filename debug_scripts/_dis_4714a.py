import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 470E0-471C0 ===")
for i in md.disasm(pe.get_data(0x470E0, 0xE0), 0x800470E0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# Also run no-stdin interactive with more detail on SO
