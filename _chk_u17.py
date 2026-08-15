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
print("broken jcc left:", text.count(b"\x0f\x00\x00\x00\x00\x00"))

# check site 14d6c
md=Cs(CS_ARCH_X86, CS_MODE_64)
off=0x14d60-text_rva
print("around 14d6c:")
for insn in md.disasm(text[off:off+48], base+0x14d60, count=12):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")

# data c8d8
for i in range(num):
    o=sec+i*40
    name=data[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
    if name==".data":
        print("c8d8", hex(struct.unpack_from("<Q", data, rp+0x8d8)[0]))
