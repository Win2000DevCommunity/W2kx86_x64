from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pathlib import Path
import struct
pe=Path('build_univ176/cmd_pure_h.exe').read_bytes()
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
rmap={}
for line in open('build_univ176/rva.txt'):
    p=line.split()
    if len(p)>=2:
        try: rmap[int(p[0],16)]=int(p[1],16)
        except: pass
print('13a9c ->', hex(rmap.get(0x13a9c,0)))
entry=rmap[0x13a9c]
print('==== pe64 entry ====')
for insn in md.disasm(blob[entry-tr:entry-tr+0xc0], 0x80000000+entry):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))