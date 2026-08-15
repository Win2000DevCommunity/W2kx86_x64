import struct
import pefile

pe = pefile.PE('build_univ355/cmd_pure.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# Find all movabs references to shim IAT slots
shim_slots = {
    0x800A4E48: 'slot0 GetVDMCurrentDirectories',
    0x800A4E50: 'slot1 InitializeCriticalSection',
    0x800A4E58: 'slot2 LeaveCriticalSection',
    0x800A4E60: 'slot3 EnterCriticalSection',
    0x800A4E68: 'slot4 VirtualQuery',
    0x800A4E70: 'slot5 InterlockedExchange',
    0x800A4E78: 'slot6 longjmp',
    0x800A4E80: 'slot7 towupper',
    0x800A4E88: 'slot8 _get_osfhandle',
    0x800A4E90: 'slot9 towlower',
    0x800A4E98: 'slot10 _except_handler3',
    0x800A4EA0: 'slot11 _setjmp3',
    0x800A4EA8: 'slot12 _seh_longjmp_unwind',
    0x800A4EB0: 'slot13 __p___initenv',
    0x800A4EB8: 'slot14 _adjust_fdiv',
    0x800A4EC0: 'slot15 __p__commode',
    0x800A4EC8: 'slot16 __p__fmode',
}

for slot_va, name in sorted(shim_slots.items()):
    # movabs r64, imm64: 48/49 B8-BF + imm64
    pattern = struct.pack('<Q', slot_va)
    pos = 0
    refs = []
    while True:
        idx = td.find(pattern, pos)
        if idx < 0:
            break
        # Check if preceded by 48/49 B8-BF
        if idx >= 2 and (td[idx-2] & 0xFE) == 0x48 and 0xB8 <= td[idx-1] <= 0xBF:
            rva = tv + idx - 2
            refs.append(rva)
        pos = idx + 1
    print(f'{name} (0x{slot_va:X}): {len(refs)} refs {[f"main+0x{r-0x1000:X}" for r in refs[:8]]}')
