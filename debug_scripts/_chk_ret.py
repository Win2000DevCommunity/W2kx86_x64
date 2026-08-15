import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

data=Path("build_univ17/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
secs=[]
for i in range(num):
    o=sec+i*40
    name=data[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
    secs.append((name,va,vs,rs,rp))
    print(name, hex(va), hex(va+vs))
text=next(s for s in secs if s[0]==".text")
_,_,_,_,rp=text; text_rva=text[1]
textb=data[rp:rp+text[3]]

md=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe 0x2470..0x24b0 ===")
off=0x2470-text_rva
for insn in md.disasm(textb[off:off+64], base+0x2470, count=20):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")

# reverse map for 2490 area
rmap={}; rev={}
for line in Path("build_univ17/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b; rev.setdefault(b,[]).append(a)
print("\nx86 for ~2496:")
for pe,xs in sorted(rev.items()):
    if 0x2470 <= pe <= 0x24b0:
        print(f"  {pe:#x} <- {[hex(x) for x in xs[:8]]}")

# What is at data 0x5d1c0?
ds=next(s for s in secs if s[0]==".data")
dva,drp=ds[1],ds[4]
off=0x5d1c0-dva
print("\n.data@5d1c0", data[drp+off:drp+off+32].hex())
print("as ascii", data[drp+off:drp+off+32])

# remaining broken jccs - are they insn-aligned after test/cmp?
# sample 20
pat=b"\x0f\x00\x00\x00\x00\x00"
i=0; n=0
while n<10:
    j=textb.find(pat,i)
    if j<0: break
    rva=text_rva+j
    ctx=textb[j-3:j+6]
    print(f"  leftover {rva:#x} ctx={ctx.hex()}")
    i=j+1; n+=1
