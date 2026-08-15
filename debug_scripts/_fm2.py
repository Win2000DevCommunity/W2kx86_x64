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
print('==== x86 PutStdOut/FormatMessage fn ====')
for insn in md.disasm(xt[0x13b20-xr:0x13bb0-xr], 0x13b20):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))

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
md64=Cs(CS_ARCH_X86, CS_MODE_64)
# find pe64 entry for this fn via rva map
rmap={}
for line in open('build_univ176/rva.txt'):
    p=line.split()
    if len(p)>=2:
        try: rmap[int(p[0],16)]=int(p[1],16)
        except: pass
print('x86 13b30 ->', hex(rmap.get(0x13b30,0)))
print('x86 13b8f ->', hex(rmap.get(0x13b8f,0)))
for xa in range(0x13b20, 0x13b90):
    if xa in rmap:
        print(hex(xa), '->', hex(rmap[xa]))
        break
entry=rmap.get(0x13b30) or rmap.get(0x13b2c) or rmap.get(0x13b40)
# search push rbp near
for rva in range(0x26200, 0x26400):
    if blob[rva-tr:rva-tr+3]==b'\x55\x48\x89' or blob[rva-tr:rva-tr+4]==b'\x40\x55\x48\x89':
        print('possible prologue', hex(rva))