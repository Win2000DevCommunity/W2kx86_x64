#!/usr/bin/env python3
import pefile, struct, sys
pe = pefile.PE(sys.argv[1])
rva = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x33F86
d = pe.get_data(rva, 32)
print(f'x64 at 0x{rva:X}:')
for j in range(0, 32, 16):
    print(f'  {d[j:j+16].hex()}')
for j in range(len(d)-9):
    if d[j:j+2] == b'\x48\xb8':
        slot = struct.unpack_from('<Q', d, j+2)[0]
        print(f'movabs rax, 0x{slot:016X} (RVA 0x{slot-0x80000000:X})')
        # Find import
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for i, imp in enumerate(entry.imports):
                s = entry.struct.FirstThunk + 0x80000000 + i*8
                if s == slot:
                    name = imp.name.decode() if imp.name else f'ord({imp.ordinal})'
                    print(f'  = {entry.dll.decode("utf-8","ignore")}!{name}')
                    break
    elif d[j:j+2] == b'\xff\x15':
        rel = struct.unpack_from('<i', d, j+2)[0]
        slot = 0x80000000 + rva + j + 6 + rel
        print(f'FF 15 -> 0x{slot:016X} (RVA 0x{slot-0x80000000:X})')
