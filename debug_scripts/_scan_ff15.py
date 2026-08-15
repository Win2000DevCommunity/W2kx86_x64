import struct
import pefile

pe = pefile.PE('build_univ355/cmd_pure.exe')
for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# Scan for FF 15 / FF 25 RIP-relative refs across the FULL shim IAT range
# Shim IAT RVAs: 0xA4E48 to 0xA4ED0
shim_lo, shim_hi = 0xA4E48, 0xA4ED0
i = 0
refs = []
while i < len(td) - 6:
    if td[i:i+2] in (b'\xff\x25', b'\xff\x15'):
        rel = struct.unpack_from('<i', td, i + 2)[0]
        rva = tv + i
        tgt = rva + 6 + rel
        if shim_lo <= tgt <= shim_hi:
            refs.append((tv + i, tgt, td[i+1]))
        i += 6
    else:
        i += 1
print(f'FF 15/25 RIP refs to shim IAT: {len(refs)}')
for r, t, op in refs[:15]:
    print(f'  main+0x{r:X}: {"jmp" if op == 0x25 else "call"} -> slot 0x{t:X}')

# Also check .data section for slot references (pointer cells)
print('\n.data refs to shim slots:')
for sec in pe.sections:
    if b'.data' in sec.Name:
        dd = sec.get_data()
        dv = sec.VirtualAddress
        break
for slot_va, name in [(0x800A4E98, 's10'), (0x800A4EA0, 's11'), (0x800A4E78, 's6')]:
    pattern = struct.pack('<Q', slot_va)
    cnt = dd.count(pattern)
    print(f'  {name} (0x{slot_va:X}): {cnt} in .data')
