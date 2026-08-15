import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
data=Path("build_univ19/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break
print("broken jcc", text.count(b"\x0f\x00\x00\x00\x00\x00"))
md=Cs(CS_ARCH_X86, CS_MODE_64)
# check ret 8 site ~2490
print("=== around 2490 ===")
for insn in md.disasm(text[0x2485-text_rva:0x24a0-text_rva], base+0x2485, count=15):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
print("=== 14d6c ===")
for insn in md.disasm(text[0x14d5d-text_rva:0x14d80-text_rva], base+0x14d5d, count=10):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
