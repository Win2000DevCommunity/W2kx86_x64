from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pathlib import Path
import struct
pe=Path('build_univ176/cmd_pure_i.exe').read_bytes()
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
print('==== 0x486bf ====')
for insn in md.disasm(blob[0x48690-tr:0x48690-tr+0x80], 0x80048690):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))
# count Application string
app=b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00'
idx=pe.find(app)
print('Application at file', hex(idx) if idx>=0 else None)
# rva of that
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    if rp<=idx<rp+rs:
        print('in',name,'va',hex(va+idx-rp), 'abs',hex(0x80000000+va+idx-rp))