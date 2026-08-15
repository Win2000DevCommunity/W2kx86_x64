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
md=Cs(CS_ARCH_X86, CS_MODE_64)
# find add rsp, 8; ret pattern near mapped 27af
rmap={}
for line in Path("build_univ19/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
print("27af->", hex(rmap.get(0x27af,0)), "27ab->", hex(rmap.get(0x27ab,0)))
pe=rmap.get(0x27ab, 0x249b)
# pe might be PE rva - convert
off = pe - text_rva if pe >= text_rva else pe
print("disasm at", hex(pe), "blob", hex(off))
for insn in md.disasm(text[off:off+32], base+(off+text_rva), count=12):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")

# count add rsp,8; ret
n=0
i=0
while True:
    j=text.find(b"\x48\x83\xc4\x08\xc3", i)
    if j<0: break
    n+=1; i=j+1
print("add rsp,8; ret count", n)
i=0; n2=0
while True:
    j=text.find(b"\x48\x83\xc4", i)
    if j<0: break
    if j+5 < len(text) and text[j+4]==0xc3:
        n2+=1
    i=j+1
print("add rsp,imm8; ret count", n2)
