from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from pathlib import Path
import struct

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
print('==== full getchar 0x448b4 ====')
for insn in md.disasm(blob[0x448b4-tr:0x448b4-tr+0x120], 0x800448b4):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))
    if insn.mnemonic=='ret':
        break

x86=Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
e=struct.unpack_from('<I',x86,0x3c)[0]
num=struct.unpack_from('<H',x86,e+6)[0]
opt=struct.unpack_from('<H',x86,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if x86[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',x86,o+8); xt=x86[rp:rp+rs]; xr=va; break
md32=Cs(CS_ARCH_X86, CS_MODE_32)
print('==== x86 B186 ====')
for insn in md32.disasm(xt[0xb186-xr:0xb186-xr+0xa0], 0xb186):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))
    if insn.mnemonic=='ret':
        break