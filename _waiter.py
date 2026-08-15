import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
import struct
text = pe.get_data(0x1000, 0x57000)
pat = bytes.fromhex("49bbe0ba05800000000041833b00")
at = text.find(pat)
print("at", hex(at+0x1000) if at>=0 else None)
# also cmp with other regs
for off in range(len(text)-12):
    if text[off:off+10] == bytes.fromhex("49bbe0ba058000000000"):
        print(hex(off+0x1000), text[off:off+16].hex())
print("\n=== 457F0-45880 ===")
for i in md.disasm(pe.get_data(0x457F0, 0xA0), 0x800457F0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
