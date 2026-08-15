# What should rcx be - dump more context at 0x9f4c and the helper purpose
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
print("=== 0x9e80..0x9f60 ===")
for insn in md.disasm(text[0x9e80-text_rva:0x9f60-text_rva], base+0x9e80, count=60):
    print(f"{insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
print("\n=== helper 0x195d2 ===")
for insn in md.disasm(text[0x195d2-text_rva:0x195f5-text_rva], base+0x195d2, count=20):
    print(f"{insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
