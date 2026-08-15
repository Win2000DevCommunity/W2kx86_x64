rmap={}
for line in open('build_univ176/rva.txt'):
    p=line.split()
    if len(p)>=2:
        try:
            a,b=int(p[0],16),int(p[1],16)
            rmap[a]=b
        except: pass
for pe64 in [0x264f0,0x26500,0x26540,0x2656f,0x14e34]:
    xs=[(a,b) for a,b in rmap.items() if abs(b-pe64)<0x10]
    xs.sort(key=lambda x: abs(x[1]-pe64))
    print('pe64 %#x near %s'%(pe64, ', '.join('%#x->%#x'%x for x in xs[:4])))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from pathlib import Path
import struct
x86=Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
e=struct.unpack_from('<I',x86,0x3c)[0]
num=struct.unpack_from('<H',x86,e+6)[0]
opt=struct.unpack_from('<H',x86,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if x86[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',x86,o+8); xt=x86[rp:rp+rs]; xr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
# find x86 mapping closest to 0x26540
near=min(rmap.items(), key=lambda kv: abs(kv[1]-0x26540))
print('using x86', hex(near[0]), '->', hex(near[1]))
xa=near[0]
for insn in md.disasm(xt[xa-0x40-xr:xa+0x40-xr], xa-0x40):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))