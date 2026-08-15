import pefile
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

BUILD = 'build_univ371'
pe = pefile.PE(f'{BUILD}/cmd_pure.exe')
text = next(s for s in pe.sections if b'.text' in s.Name)
d = text.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

base_lo = 0x6339C
print('branches in island [0x6339C, 0x638DC):')
for ins in md.disasm(d[base_lo:0x638DC], base_lo):
    if ins.mnemonic.startswith('j') or ins.mnemonic in ('call', 'jmp'):
        tgt = None
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                tgt = op.imm
        print(f'  blob+0x{ins.address:X}: {ins.mnemonic} -> '
              f'{hex(tgt) if tgt is not None else "ind"}')
