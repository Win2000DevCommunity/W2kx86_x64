import struct
import pefile

pe86 = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
for sec in pe86.sections:
    if b'.text' in sec.Name:
        td86 = sec.get_data()
        tv86 = sec.VirtualAddress
        break

# Find x86 FF 15 calls to longjmp (0x11D4)
longjmp_va = pe86.OPTIONAL_HEADER.ImageBase + 0x11D4
pattern = b'\xFF\x15' + struct.pack('<I', longjmp_va)
pos = 0
sites = []
while True:
    idx = td86.find(pattern, pos)
    if idx < 0:
        break
    sites.append(tv86 + idx)
    pos = idx + 1
print(f'x86 longjmp FF15 sites: {len(sites)}')

# x86 FF 15 to towupper (0x11E4)
tu_va = pe86.OPTIONAL_HEADER.ImageBase + 0x11E4
pattern = b'\xFF\x15' + struct.pack('<I', tu_va)
pos = 0
sites_tu = []
while True:
    idx = td86.find(pattern, pos)
    if idx < 0:
        break
    sites_tu.append(tv86 + idx)
    pos = idx + 1
print(f'x86 towupper FF15 sites: {len(sites_tu)}')

# Now in the x64 output, find the corresponding translated sites
# We can't map directly without rva_map, but we CAN check which x64 slots
# are referenced near the translated positions.
# Instead, let's count total movabs refs per slot across the whole image
pe = pefile.PE('build_univ358/cmd_pure.exe')
for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        break

slot_names = {
    0x800A4E48: 's0 GetVDM', 0x800A4E50: 's1 InitCS', 0x800A4E58: 's2 LeaveCS',
    0x800A4E60: 's3 EnterCS', 0x800A4E68: 's4 VirtualQuery',
    0x800A4E70: 's5 InterlockedEx', 0x800A4E78: 's6 longjmp',
    0x800A4E80: 's7 towupper', 0x800A4E88: 's8 get_osfhandle',
    0x800A4E90: 's9 towlower', 0x800A4E98: 's10 except_handler3',
    0x800A4EA0: 's11 setjmp3', 0x800A4EA8: 's12 seh_lj_unwind',
    0x800A4EB0: 's13 p_initenv', 0x800A4EB8: 's14 adjust_fdiv',
    0x800A4EC0: 's15 p_commode', 0x800A4EC8: 's16 p_fmode',
}
counts = {}
for slot_va in slot_names:
    pattern = struct.pack('<Q', slot_va)
    counts[slot_va] = td.count(pattern)
for slot_va in sorted(slot_names):
    print(f'  {slot_names[slot_va]} (0x{slot_va:X}): {counts[slot_va]} raw occurrences')
