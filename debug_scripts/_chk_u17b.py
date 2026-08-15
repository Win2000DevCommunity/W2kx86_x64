import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

data=Path("build_univ17/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break

off=0x14d5d-text_rva
print("hex", text[off:off+40].hex())
md=Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(text[off:off+40], base+0x14d5d, count=15):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")

# Compare: was first jcc patched to wrong place overlapping?
# Expected: 48 c7 c0 00 04 00 00 | 89 45 bc | 8b 4d c8 | 85 c9 | 0f 84 xx xx xx xx | 66 83 39 00 | 0f 84 ...
