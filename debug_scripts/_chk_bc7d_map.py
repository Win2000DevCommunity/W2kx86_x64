from pathlib import Path
rmap={}
rev={}
for line in Path("build_univ96/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    oa,nb=int(a,16),int(b,16)
    rmap[oa]=nb
    rev.setdefault(nb,[]).append(oa)
# find x86 near 0x565be
target=0x565be
# find closest mapped
cands=[(abs(nb-target),oa,nb) for oa,nb in rmap.items()]
cands.sort()
print("nearest maps to 565be:")
for d,oa,nb in cands[:15]:
    print(f"  x86 {oa:#x} -> {nb:#x} delta={d:#x}")
# also search for all mov [fbc8], fbe2 style in pe - both imms
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
pe=Path("build_univ96/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
code=pe[rp:rp+rs]
md=Cs(CS_ARCH_X86,CS_MODE_64)
# find pattern: mov dword [reg], 0x8006cbe2 OR 0x8001fbe2 after movabs ...cbc8
for imm in (0x8001fbe2, 0x8006cbe2):
    pat=struct.pack("<I",imm)
    idx=0
    print(f"\n=== stores of {imm:#x} ===")
    while True:
        j=code.find(pat,idx)
        if j<0: break
        # look back for c700 / c7xx
        ctx=code[max(0,j-12):j+4]
        # if c7 00 or similar just before
        for back in range(1,8):
            if j-back>=0 and code[j-back]==0xc7:
                rva=va+j
                print(f"  @{rva-back:#x}: {code[j-back:j+4].hex()}")
                # map back
                nearest=min(rmap.items(), key=lambda kv: abs(kv[1]-(rva-back)))
                print(f"    nearest x86 {nearest[0]:#x} -> {nearest[1]:#x}")
                break
        idx=j+1
