from capstone import Cs, CS_ARCH_X86, CS_MODE_32
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
print('==== x86 too-long path ====')
for insn in md.disasm(xt[0xafd6-xr:0xb010-xr], 0xafd6):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))
print('==== 13a62 / 13a9c ====')
for insn in md.disasm(xt[0x13a62-xr:0x13a9c-xr], 0x13a62):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))