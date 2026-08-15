import struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pefile.PE('build_univ355/cmd_pure.exe')
for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Find ALL movabs rax, <shim slot> followed by jmp rax (thunk pattern)
# vs call rax (call site pattern)
for slot_va, name in [(0x800A4E98, 'slot10'), (0x800A4EA0, 'slot11')]:
    pattern = struct.pack('<Q', slot_va)
    pos = 0
    while True:
        idx = td.find(pattern, pos)
        if idx < 0:
            break
        if idx >= 2 and (td[idx-2] & 0xFE) == 0x48 and 0xB8 <= td[idx-1] <= 0xBF:
            start = idx - 2
            code = bytes(td[start:start+20])
            insns = list(md.disasm(code, 0x80000000 + tv + start))
            kind = 'UNKNOWN'
            for ins in insns:
                if ins.mnemonic == 'jmp':
                    kind = 'THUNK (jmp)'
                    break
                if ins.mnemonic == 'call':
                    kind = 'CALL SITE'
                    break
            print(f'  main+0x{tv+start:X}: {name} {kind}')
        pos = idx + 1
