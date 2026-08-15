from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from pathlib import Path
import struct

rmap={}
for line in open('build_univ176/rva.txt'):
    p=line.split()
    if len(p)>=2:
        try: rmap[int(p[0],16)]=int(p[1],16)
        except: pass

for pe64 in [0x448b4, 0x15158, 0xb186, 0x14e25]:
    xs=[a for a,b in rmap.items() if b==pe64]
    if xs:
        print('pe64 %#x <- x86 %s'%(pe64, ' '.join('%#x'%a for a in xs[:5])))
    else:
        near=min(rmap.items(), key=lambda kv: abs(kv[1]-pe64))
        print('pe64 %#x nearest x86 %#x->%#x'%(pe64, near[0], near[1]))

pe=Path('build_univ176/cmd_pure_f.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if pe[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
        blob=pe[rp:rp+rs]; tr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_64)
print('==== 0x448b4 ====')
for insn in md.disasm(blob[0x448b4-tr:0x448b4-tr+0x50], 0x800448b4):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))

# Echo body pe64 after setjmp fallthrough - full until ret
print('==== Echo body from 0x149b8 ====')
count=0
for insn in md.disasm(blob[0x149b8-tr:0x149b8-tr+0x400], 0x800149b8):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))
    count+=1
    if insn.mnemonic=='ret' and count>20: break
    if count>120: break