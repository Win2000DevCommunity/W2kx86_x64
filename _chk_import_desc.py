#!/usr/bin/env python3
"""Check raw import directory descriptor for w2kshim64 imports."""
import pefile, struct, sys

pe = pefile.PE(sys.argv[1])

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8', 'ignore')
    if 'w2kshim' not in dll.lower():
        continue
    
    s = entry.struct
    print(f"DLL: {dll}")
    print(f"  OriginalFirstThunk (ILT): 0x{s.OriginalFirstThunk:X}")
    print(f"  TimeDateStamp: 0x{s.TimeDateStamp:08X}")
    print(f"  ForwarderChain: 0x{s.ForwarderChain:X}")
    print(f"  Name RVA: 0x{s.Name:X}")
    print(f"  FirstThunk (IAT): 0x{s.FirstThunk:X}")
    
    # Read ILT entries directly
    data = open(sys.argv[1], 'rb').read()
    
    def rva_to_file(rva):
        for sec in pe.sections:
            lo = sec.VirtualAddress
            hi = lo + sec.Misc_VirtualSize
            if lo <= rva < hi:
                return sec.PointerToRawData + (rva - lo)
        return None
    
    ilt_off = rva_to_file(s.OriginalFirstThunk)
    iat_off = rva_to_file(s.FirstThunk)
    
    print(f"\n  ILT at file offset 0x{ilt_off:X}:")
    for i in range(20):
        off = ilt_off + i * 8
        val = struct.unpack_from('<Q', data, off)[0]
        if val == 0:
            print(f"    [{i:2d}] NULL")
            break
        if val & (1 << 63):
            print(f"    [{i:2d}] ORDINAL {val & 0xFFFF}")
        else:
            name_rva = val & 0x7FFFFFFF
            n_off = rva_to_file(name_rva)
            hint = struct.unpack_from('<H', data, n_off)[0]
            end = data.find(b'\x00', n_off + 2)
            name = data[n_off+2:end].decode('ascii','replace')
            print(f"    [{i:2d}] NAME hint=0x{hint:04X} name={name}")
    
    print(f"\n  IAT at file offset 0x{iat_off:X}:")
    for i in range(20):
        off = iat_off + i * 8
        val = struct.unpack_from('<Q', data, off)[0]
        if val == 0:
            print(f"    [{i:2d}] NULL")
            break
        # IAT entries are just VA pointers (0-filled initially, filled by loader)
        # In the file, they should match ILT or be 0
        print(f"    [{i:2d}] 0x{val:016X}")
