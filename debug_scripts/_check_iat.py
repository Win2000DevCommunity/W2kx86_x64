import pefile
import struct

pe = pefile.PE('build_univ351/cmd_pure.exe')

for sec in pe.sections:
    if b'.idata' in sec.Name:
        idata_va = sec.VirtualAddress
        idata_raw = sec.PointerToRawData
        break

# Check the hint/name entry that the IAT slot points to
# The IAT slot at 0xA4650 contains 0xA4D15 (the ILT entry)
# So the hint/name entry is at RVA 0xA4D15
rva = 0xA4D15
file_off = rva - idata_va + idata_raw
hint = struct.unpack_from('<H', pe.__data__, file_off)[0]
name_end = pe.__data__.find(b'\x00', file_off + 2)
name = pe.__data__[file_off + 2:name_end].decode()
print(f'RVA 0x{rva:X} hint=0x{hint:04X} ({hint}) name="{name}"')

# Check nearby hint/name entries
print('\nHint/name entries for nearby IAT slots:')
iat_slots_rva = [0xA4CD0, 0xA4CDC, 0xA4CEF, 0xA4D00, 0xA4D15, 0xA4D21, 0xA4D33, 0xA4D48]
for srva in iat_slots_rva:
    fo = srva - idata_va + idata_raw
    h = struct.unpack_from('<H', pe.__data__, fo)[0]
    ne = pe.__data__.find(b'\x00', fo + 2)
    n = pe.__data__[fo + 2:ne].decode()
    print(f'  0x{srva:X}: hint={h} name="{n}"')

print()

# Now check the ACTUAL import entries for kernel32 to find which function has
# its ILT entry at RVA 0xA4D15
print('Kernel32 imports sorted by address:')
kernel32_imports = []
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if entry.dll.lower() == b'kernel32.dll':
        for imp in entry.imports:
            kernel32_imports.append((imp.address, imp.name.decode() if imp.name else '(ordinal)', imp.hint))
        break

kernel32_imports.sort()
for addr, name, hint in kernel32_imports:
    marker = ' <--- GetCPInfo' if 'GetCPInfo' in name else ''
    print(f'  RVA=0x{addr:X} hint=0x{hint:04X} name={name}{marker}')
