from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
obase = struct.unpack_from("<I", src, e+24+28)[0]
num = struct.unpack_from("<H", src, e+6)[0]
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
        xt=src[rp:rp+rs]; xtr=va; break
rmap={}
for line in Path("build_univ18/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
P=0x14d6c
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
JCC_CC={'je':0x84,'jz':0x84,'jne':0x85,'jnz':0x85,'jl':0x8c,'jnge':0x8c,'jg':0x8f,'jnle':0x8f,'jle':0x8e,'jng':0x8e,'jge':0x8d,'jnl':0x8d,'jb':0x82,'jnae':0x82,'jc':0x82,'ja':0x87,'jnbe':0x87,'jbe':0x86,'jna':0x86,'jae':0x83,'jnb':0x83,'jnc':0x83,'js':0x88,'jns':0x89,'jo':0x80,'jno':0x81,'jp':0x8a,'jpe':0x8a,'jnp':0x8b,'jpo':0x8b}
cands=[]
for xrva,pe in rmap.items():
    if not (P-96 <= pe <= P): continue
    off=xrva-xtr
    if off<0 or off+6>len(xt): continue
    b0=xt[off]
    if not (b0==0x0F or 0x70<=b0<=0x7F): continue
    ins=list(md.disasm(xt[off:off+16], obase+xrva, count=1))
    if not ins: continue
    insn=ins[0]
    if not insn.mnemonic.startswith('j') or insn.mnemonic=='jmp': continue
    cc=JCC_CC.get(insn.mnemonic)
    if cc is None: continue
    gap=P-pe
    cands.append((gap,xrva,pe,insn.mnemonic,cc,insn.bytes.hex()))
cands.sort()
print("top 15 candidates:")
for c in cands[:15]:
    print(f"  gap={c[0]:#x} xrva={c[1]:#x} pe={c[2]:#x} {c[3]} cc={c[4]:#x} {c[5]}")
