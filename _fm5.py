from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pathlib import Path
import struct
pe=Path('build_univ176/cmd_pure_h.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
ib=struct.unpack_from('<Q',pe,e+24+24)[0]
sec=e+24+opt
secs={}
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    secs[name]=(va,rp,rs)
    if name==b'.text':
        blob=pe[rp:rp+rs]; tr=va; text_rp=rp
md=Cs(CS_ARCH_X86, CS_MODE_64)
# find jmps to 0x26530-0x26570
for insn in md.disasm(blob, ib+tr):
    if insn.mnemonic in ('jmp','call') and insn.op_str.startswith('0x'):
        tgt=int(insn.op_str,16)-ib
        if 0x26530 <= tgt <= 0x26570:
            print('%06x: %s %s'%(insn.address-ib, insn.mnemonic, insn.op_str))

# check IAT slot 0x84590
slot=0x84590
for name,(va,rp,rs) in secs.items():
    if va<=slot<va+rs:
        off=rp+(slot-va)
        print('slot',name, hex(struct.unpack_from('<Q',pe,off)[0]))

# scan mov rbx / mov ebx between 26150 and 2656f
print('rbx writes:')
for insn in md.disasm(blob[0x26150-tr:0x26570-tr], ib+0x26150):
    if insn.mnemonic=='mov' and (insn.op_str.startswith('rbx') or insn.op_str.startswith('ebx')):
        print('  %06x: %s %s'%(insn.address-ib, insn.mnemonic, insn.op_str))