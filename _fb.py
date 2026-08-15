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
# find 0x3000 immediates and lea rbp-0x14 near PutMsg
for insn in md.disasm(blob[0x26280-tr:0x26400-tr], 0x80026280):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))