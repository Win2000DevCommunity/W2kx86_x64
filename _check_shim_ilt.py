import struct
import pefile

pe = pefile.PE('build_univ351/cmd_pure.exe')

# Find .idata section
for sec in pe.sections:
    if b'.idata' in sec.Name:
        idata_va = sec.VirtualAddress
        idata_raw = sec.PointerToRawData
        break

# Shim ILT RVA is 0xA4DB8 (from import directory)
ilt_rva = 0xA4DB8
# Shim IAT starts at 0x800A4E48 (first import address)
iat_start_rva = 0xA4E48

print("Shim ILT entries:")
for i in range(17):
    ilt_rva_slot = ilt_rva + i * 8
    iat_rva_slot = iat_start_rva + i * 8
    
    # Read ILT entry
    ilt_file = ilt_rva_slot - idata_va + idata_raw
    ilt_val = struct.unpack_from('<Q', pe.__data__, ilt_file)[0]
    
    # Read IAT entry (same as ILT before loading)
    iat_file = iat_rva_slot - idata_va + idata_raw
    iat_val = struct.unpack_from('<Q', pe.__data__, iat_file)[0]
    
    # Check if ordinal (high bit set)
    is_ord = (ilt_val >> 63) & 1
    if is_ord:
        ordinal = ilt_val & 0xFFFF
        print(f'  [{i}] ILT=0x{ilt_val:016X} ORDINAL={ordinal} IAT=0x{iat_val:016X}')
    else:
        # Name import: ILT value is RVA to hint/name
        hint_rva = ilt_val & 0x7FFFFFFF
        hint_file = hint_rva - idata_va + idata_raw
        hint = struct.unpack_from('<H', pe.__data__, hint_file)[0]
        name_end = pe.__data__.find(b'\x00', hint_file + 2)
        name = pe.__data__[hint_file + 2:name_end].decode('ascii', errors='replace')
        print(f'  [{i}] ILT=0x{ilt_val:016X} name={hint}:{name} IAT=0x{iat_val:016X}')

print()
print("Ordinal mapping (what the import says vs what the shim has):")
for i in range(17):
    ilt_file = (ilt_rva + i * 8) - idata_va + idata_raw
    ilt_val = struct.unpack_from('<Q', pe.__data__, ilt_file)[0]
    is_ord = (ilt_val >> 63) & 1
    if is_ord:
        ordinal = ilt_val & 0xFFFF
        # What function is at this ordinal in the shim?
        # We know from previous output:
        shim_funcs = {
            1: 'DllMain', 2: 'InterlockedExchange', 3: '_setjmp3',
            4: 'longjmp', 5: '_except_handler3', 6: '_seh_longjmp_unwind',
            7: '_adjust_fdiv', 8: '__p___initenv', 9: '__p__commode',
            10: '__p__fmode', 11: 'towupper', 12: 'towlower',
            13: 'VirtualQuery', 14: '_get_osfhandle', 15: 'GetVDMCurrentDirectories',
            16: 'InitializeCriticalSection', 17: 'EnterCriticalSection',
            18: 'LeaveCriticalSection', 19: 'DeleteCriticalSection'
        }
        expected = shim_funcs.get(ordinal, 'UNKNOWN')
        print(f'  Slot {i}: imports ordinal {ordinal} -> {expected}')
