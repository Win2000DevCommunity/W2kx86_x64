import struct
import pefile

pe = pefile.PE('build_univ355/cmd_pure.exe')
for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

# Find RIP-relative FF 25/FF 15 refs to the shim IAT range
i = 0
refs = []
while i < len(td) - 6:
    if td[i:i+2] in (b'\xff\x25', b'\xff\x15'):
        rel = struct.unpack_from('<i', td, i + 2)[0]
        rva = tv + i
        tgt = rva + 6 + rel
        if 0xA4E90 <= tgt <= 0xA4ED0:
            refs.append((tv + i, tgt))
        i += 6
    else:
        i += 1
print(f'FF 25/15 RIP refs to shim IAT range: {len(refs)}')
for r, t in refs[:12]:
    print(f'  0x{r:X} -> slot 0x{t:X}')

# Also search for movabs references with all forms
print('\nmovabs refs to 0x800A4EA0 (_setjmp3):')
pattern = struct.pack('<Q', 0x800A4EA0)
pos = 0
cnt = 0
while True:
    idx = td.find(pattern, pos)
    if idx < 0:
        break
    cnt += 1
    pos = idx + 1
print(f'  {cnt} occurrences')

# What does the code around the x86 thunk 0x1A766 map to? Find the thunk
# translation by looking for movabs + indirect call to slot 11
print('\nSearching for slot 11 (0x800A4EA0) references ANYWHERE in image:')
img = pe.get_memory_mapped_image()
cnt2 = 0
pos = 0
while True:
    idx = img.find(pattern, pos)
    if idx < 0:
        break
    cnt2 += 1
    pos = idx + 1
print(f'  {cnt2} occurrences in full image')
