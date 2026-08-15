import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# map pe64 rva -> x86 via rva.txt
rmap={}
inv={}
for line in open('build_univ176/rva.txt'):
    parts=line.split()
    if len(parts)>=2:
        try:
            a,b=int(parts[0],16),int(parts[1],16)
            rmap[a]=b; inv.setdefault(b,a)
        except: pass

for pe64 in [0x14974,0x1498d,0x149ac,0x1ea3c,0x1ea8b,0x4578c,0x4580b,0x1c5f8]:
    # find x86 that maps near this
    xs=[(a,b) for a,b in rmap.items() if b==pe64]
    if not xs:
        # nearest
        near=min(rmap.items(), key=lambda kv: abs(kv[1]-pe64))
        print('pe64 %#x nearest x86 %#x -> %#x (delta %d)'%(pe64, near[0], near[1], near[1]-pe64))
    else:
        print('pe64 %#x <- x86 %s'%(pe64, ' '.join('%#x'%a for a,_ in xs[:5])))

# disasm x86 cmd around likely PutMsg / echos
x86=Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
e=struct.unpack_from('<I',x86,0x3c)[0]
num=struct.unpack_from('<H',x86,e+6)[0]
opt=struct.unpack_from('<H',x86,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if x86[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',x86,o+8)
        xt=x86[rp:rp+rs]; xr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
# find x86 for pe64 0x14974
x149=None
for a,b in rmap.items():
    if b==0x14974: x149=a; break
if x149 is None:
    x149=min(rmap, key=lambda a: abs(rmap[a]-0x14974))
print('using x86 %#x for 14974 (maps to %#x)'%(x149, rmap[x149]))
off=x149-xr
for insn in md.disasm(xt[off:off+0x80], x149):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))