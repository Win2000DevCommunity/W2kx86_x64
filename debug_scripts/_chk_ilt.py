#!/usr/bin/env python3
"""Check raw ILT entries for w2kshim imports in x64 binary."""
import pefile, struct, sys

pe = pefile.PE(sys.argv[1])

# Find w2kshim import directory entry
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8', 'ignore')
    if 'w2kshim' not in dll.lower():
        continue
    
    print(f"DLL: {dll}")
    print(f"  ILT RVA: 0x{entry.struct.OriginalFirstThunk:X}")
    print(f"  IAT RVA: 0x{entry.struct.FirstThunk:X}")
    
    # Read ILT entries (8 bytes each, terminated by NULL)
    ilt_rva = entry.struct.OriginalFirstThunk
    iat_rva = entry.struct.FirstThunk
    
    # Find offset
    for sec in pe.sections:
        lo = sec.VirtualAddress
        hi = lo + sec.Misc_VirtualSize
        if lo <= ilt_rva < hi:
            ilt_off = sec.PointerToRawData + (ilt_rva - lo)
            break
    
    data = pe.__data__ if hasattr(pe, '__data__') else open(sys.argv[1], 'rb').read()
    
    print(f"\n  Raw ILT entries:")
    for i in range(20):
        off = ilt_off + i * 8
        if off + 8 > len(data):
            break
        val = struct.unpack_from('<Q', data, off)[0]
        if val == 0:
            print(f"    [{i}] NULL (end)")
            break
        if val & (1 << 63):
            ord_val = val & 0xFFFF
            print(f"    [{i}] ORDINAL {ord_val} (0x{ord_val:X})")
        else:
            # By name: bits 30-0 = RVA of hint/name
            name_rva = val & 0x7FFFFFFF
            # Read hint/name
            for sec2 in pe.sections:
                lo2 = sec2.VirtualAddress
                hi2 = lo2 + sec2.Misc_VirtualSize
                if lo2 <= name_rva < hi2:
                    name_off = sec2.PointerToRawData + (name_rva - lo2)
                    hint = struct.unpack_from('<H', data, name_off)[0]
                    name_end = data.find(b'\x00', name_off + 2)
                    name_str = data[name_off + 2:name_end].decode('ascii', errors='replace')
                    print(f"    [{i}] NAME hint=0x{hint:04X} name={name_str}")
                    break
