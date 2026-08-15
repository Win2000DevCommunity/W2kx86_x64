import sys
sys.path.insert(0, '.')

from x86x64.pe.image32 import PE32Image
from x86x64.dispatch.transform import transform_imports

pe = PE32Image(open(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe', 'rb').read())
imports = pe.parse_imports()
transformed = transform_imports(imports)

print('Shim imports after transform:')
for imp in transformed:
    if imp['dll'].lower() == 'w2kshim64.dll':
        for i, fn in enumerate(imp['functions']):
            print(f'  [{i}] ordinal={fn.get("ordinal")} iat_rva=0x{fn.get("iat_rva", 0):X} '
                  f'name={fn.get("name")}')

# Replicate _plan_import_iat_map
idata_rva = 0xA4000
desc_bytes = (len(transformed) + 1) * 20
cursor = (desc_bytes + 7) & ~7
layouts = []
for imp in transformed:
    nfuncs = len(imp['functions'])
    cursor = (cursor + 7) & ~7
    ilt_off = cursor
    cursor += (nfuncs + 1) * 8
    iat_off = cursor
    cursor += (nfuncs + 1) * 8
    name_off = cursor
    dll_name = imp['dll'].encode('ascii') + b'\x00'
    cursor += len(dll_name)
    func_entries = []
    for fn in imp['functions']:
        if fn.get('name'):
            hint_off = cursor
            cursor += 2 + len(fn['name'].encode('ascii')) + 1
            func_entries.append((fn, hint_off))
        else:
            func_entries.append((fn, None))
    layouts.append({'iat_off': iat_off, 'func_entries': func_entries})

iat_map = {}
for imp, lay in zip(transformed, layouts):
    dll = imp['dll'].lower()
    for fn_idx, (fn, hint_off) in enumerate(lay['func_entries']):
        new_rva = idata_rva + lay['iat_off'] + fn_idx * 8
        old_rva = fn.get('iat_rva', 0)
        if old_rva:
            iat_map[old_rva] = new_rva

print('\nIAT map for SEH functions (computed):')
for old in (0x1260, 0x1264, 0x1284):
    print(f'  x86 0x{old:X} -> x64 0x{iat_map.get(old, 0):X}')

# Check the built PE's actual shim slots
import pefile
built = pefile.PE('build_univ355/cmd_pure.exe')
print('\nBuilt PE shim IAT slots:')
for entry in built.DIRECTORY_ENTRY_IMPORT:
    if entry.dll.lower() == b'w2kshim64.dll':
        for i, imp in enumerate(entry.imports):
            print(f'  slot {i}: addr=0x{imp.address:X}')
        break

# Now check the shim ILT ordinals in the built PE
print('\nBuilt PE shim ILT ordinals:')
for sec in built.sections:
    if b'.idata' in sec.Name:
        idata_va = sec.VirtualAddress
        idata_raw = sec.PointerToRawData
        break
import struct
for entry in built.DIRECTORY_ENTRY_IMPORT:
    if entry.dll.lower() == b'w2kshim64.dll':
        ilt_rva = entry.struct.OriginalFirstThunk
        for i in range(17):
            file_off = ilt_rva - idata_va + idata_raw + i * 8
            val = struct.unpack_from('<Q', built.__data__, file_off)[0]
            print(f'  slot {i}: ILT=0x{val:016X} ordinal={val & 0xFFFF}')
        break
