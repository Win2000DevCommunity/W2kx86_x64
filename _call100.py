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
md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
# find call rbx / call rax near 0x100 immediates in echo region
for insn in md.disasm(blob[0x14974-tr:0x14e30-tr], 0x80014974):
    if insn.mnemonic=='call' and insn.op_str in ('rbx','rax','rcx','rdx','rdi','rsi','r15','r11'):
        print('%06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))
    if '0x100' in insn.op_str or insn.op_str=='ebx':
        if insn.mnemonic in ('mov','cmp','call'):
            print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))