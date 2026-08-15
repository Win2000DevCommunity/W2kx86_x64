import pefile
pe = pefile.PE("build_univ257/cmd_pure.exe")
# raw at 4581E
b = pe.get_data(0x4581E, 0x40)
print(b.hex())
# annotate
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(b, 0x8004581E):
    print(f"{i.address-0x80000000:06X} {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")
