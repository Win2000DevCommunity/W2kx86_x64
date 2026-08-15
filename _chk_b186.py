import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

data = Path("build_univ15/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", data, 0x3c)[0]
soh = struct.unpack_from("<H", data, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", data, e+6)[0]
base = struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break

# fbc8 in .data: old 0x4ad1fbc8 -> rva 0x1fbc8 -> off into .data 0x3bc8
# new .data at 0x5c000 -> VA 0x8005fbc8?  0x5c000+(0x1fbc8-0x1c000)=0x5c000+0x3bc8=0x5fbc8
# So look for movabs with 0x8005fbc8
needle = struct.pack("<Q", 0x8005fbc8)
idxs=[]
i=0
while True:
    j=text.find(needle,i)
    if j<0: break
    idxs.append(text_rva+j)
    i=j+1
print("movabs imm 0x8005fbc8 at RVAs:", [hex(x) for x in idxs])

md=Cs(CS_ARCH_X86, CS_MODE_64)
for rva in idxs[:8]:
    # back up to find insn start - look for 49 bb or 48 bb etc
    off=rva-text_rva
    start=max(0, off-16)
    print(f"\n--- around {rva:#x} ---")
    for insn in md.disasm(text[start:off+48], base+text_rva+start, count=15):
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

# Also search rva map for any unique pe targets near materialized missing functions
# Check if b186 was materialized elsewhere
rmap={}
rev={}
for line in Path("build_univ15/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
    rev.setdefault(b,[]).append(a)

# pe addresses that ONLY map from b186-ish range
print("\nAll maps from 0xb180-0xb1e0:")
for a in range(0xb180, 0xb1e0):
    if a in rmap:
        print(f"  {a:#x}->{rmap[a]:#x}")
