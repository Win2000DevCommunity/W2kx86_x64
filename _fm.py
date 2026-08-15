from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
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
# find function start before 0x26540
print('==== pe64 0x26400.. ====')
for insn in md.disasm(blob[0x263e0-tr:0x26580-tr], 0x800263e0):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))

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
print('==== x86 0x13bb0 FormatMessage wrapper ====')
for insn in md32.disasm(xt[0x13bb0-xr:0x13c60-xr], 0x13bb0):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))