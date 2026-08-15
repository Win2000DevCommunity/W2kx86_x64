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

# Find all refs to shim slot 10 (0x800A4E98) and slot 11 (0x800A4EA0)
import struct as st
for slot_va, name in [(0x800A4E98, '_except_handler3'), (0x800A4EA0, '_setjmp3')]:
    pattern = st.pack('<Q', slot_va)
    pos = 0
    refs = []
    while True:
        idx = td.find(pattern, pos)
        if idx < 0:
            break
        if idx >= 2 and (td[idx-2] & 0xFE) == 0x48 and 0xB8 <= td[idx-1] <= 0xBF:
            refs.append(idx - 2)
        pos = idx + 1
    print(f'{name} slot 0x{slot_va:X}: {len(refs)} refs at text offsets {[f"0x{r:X}" for r in refs[:6]]}')

# Disassemble the FIRST _except_handler3 ref to see what x86 call it is
# (a _setjmp3 call should have push-like setup: 4 args)
target = None
pattern = st.pack('<Q', 0x800A4E98)
idx = td.find(pattern)
if idx >= 2:
    target = idx - 2
print(f'\nFirst _except_handler3 ref at text offset 0x{target:X} (RVA 0x{target+tv:X}):')

start = max(0, target - 80)
end = target + 40
for ins in md.disasm(bytes(td[start:end]), 0x80000000 + tv + start):
    off = ins.address - 0x80000000
    marker = ''
    if '0x800a4e' in ins.op_str:
        marker = '  <<< SHIM IAT REF'
    print(f'  main+0x{off:X}: {ins.mnemonic} {ins.op_str}{marker}')
