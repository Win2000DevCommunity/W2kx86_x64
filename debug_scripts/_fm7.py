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
print('==== 13cf5 ====')
for insn in md.disasm(xt[0x13cf5-xr:0x13cf5-xr+0x80], 0x13cf5):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))
    if insn.address>0x13d50 and insn.mnemonic=='ret': break

rmap={}
for line in open('build_univ176/rva.txt'):
    p=line.split()
    if len(p)>=2:
        try: rmap[int(p[0],16)]=int(p[1],16)
        except: pass
print('13a7f', hex(rmap.get(0x13a7f,0)), '13cf5', hex(rmap.get(0x13cf5,0)), '13eea', hex(rmap.get(0x13eea,0)))
print('aff3', hex(rmap.get(0xaff3,0)), 'afeb', hex(rmap.get(0xafeb,0)))