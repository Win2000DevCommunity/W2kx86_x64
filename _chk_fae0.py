from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import read_text_section, load_map
import struct

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md32=Cs(CS_ARCH_X86, CS_MODE_32)

# Find all writers to fae0
needle=struct.pack("<I", 0x4ad1fae0)
print("=== x86 refs to fae0 ===")
pos=0
while True:
    i=text.find(needle, pos)
    if i<0: break
    start=max(0,i-10)
    print(f"\n@ {text_rva+i:#x}")
    for insn in md32.disasm(text[start:i+8], base+text_rva+start, count=6):
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
    pos=i+1

# Who calls 0xadd9?
print("\n=== callers of 0xadd9 (E8 rel) ===")
# E8 rel32 where target = add9
for i in range(len(text)-5):
    if text[i]==0xE8:
        rel=struct.unpack_from("<i", text, i+1)[0]
        tgt = text_rva+i+5+rel
        if tgt==0xadd9:
            print(f"  call from {text_rva+i:#x}")

# Function containing 0xff3f from summary
print("\n=== x86 around 0xff20 (caller of helper) ===")
for insn in md32.disasm(text[0xff20-text_rva:0xff80-text_rva], base+0xff20, count=30):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
