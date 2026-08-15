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

# any rel32 (E8/E9/0F8x) targeting 0x2491-0x2497
print("Branches to epilogue 0x2491-0x2497:")
for i in range(len(text)-6):
    if text[i]==0xE8 or text[i]==0xE9:
        rel=struct.unpack_from("<i", text, i+1)[0]
        tgt=text_rva+i+5+rel
        if 0x2491 <= tgt <= 0x2497:
            print(f"  {text_rva+i:#x} {text[i]:02x} -> {tgt:#x}")
    if text[i]==0x0F and text[i+1]>=0x80 and text[i+1]<=0x8F:
        rel=struct.unpack_from("<i", text, i+2)[0]
        tgt=text_rva+i+6+rel
        if 0x2491 <= tgt <= 0x2497:
            print(f"  {text_rva+i:#x} jcc -> {tgt:#x}")

# Also check 27af / previous function body - where does it live?
rmap={}
for line in Path("build_univ20/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
print("\nPrevious fn maps:")
for a in range(0x2780, 0x27b5):
    if a in rmap:
        print(f"  {a:#x} -> {rmap[a]:#x}")

# Disasm previous function's real epilogue location  
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=rmap.get(0x27ab)
if pe:
    # pe is PE rva from dump
    off=pe-text_rva
    print(f"\nEpilogue at pe {pe:#x}:")
    for insn in md.disasm(text[off-8:off+16], base+pe-8, count=12):
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
