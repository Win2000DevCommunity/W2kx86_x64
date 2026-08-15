import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
data=Path("build_univ20/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break
md=Cs(CS_ARCH_X86, CS_MODE_64)
off=0x35ff5-text_rva
for insn in md.disasm(text[off:off+32], base+0x35ff5, count=15):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():18}  {insn.mnemonic} {insn.op_str}")
