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
cands=[(xr,pe) for xr,pe in rmap.items() if P-96 <= pe <= P]
cands.sort()
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
print("candidates claiming placeholder", hex(P))
for xr,pe in cands:
    off=xr-xtr
    b0=xt[off]
    if not (b0==0x0F or 0x70<=b0<=0x7F):
        continue
    ins=list(md.disasm(xt[off:off+16], obase+xr, count=1))
    if not ins: continue
    insn=ins[0]
    if not insn.mnemonic.startswith('j') or insn.mnemonic=='jmp':
        continue
    print(f"  x86 {xr:#x} pe {pe:#x} : {insn.mnemonic} {insn.op_str} bytes={insn.bytes.hex()}")
