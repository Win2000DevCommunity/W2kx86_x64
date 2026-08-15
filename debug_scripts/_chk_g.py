from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pathlib import Path
import struct
pe=Path('build_univ176/cmd_pure_g.exe').read_bytes()
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
print('==== refill ====')
for insn in md.disasm(blob[0x48530-tr:0x48530-tr+0xd0], 0x80048530):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))
    if insn.address>0x800485f0: break
print('==== getchar reload ====')
for insn in md.disasm(blob[0x448cb-tr:0x448cb-tr+0x50], 0x800448cb):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))