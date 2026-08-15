#!/usr/bin/env python3
"""Dump a PE section table, trying both plausible section-table origins.

Written to investigate legacy outputs whose ``SizeOfOptionalHeader`` does not
match the number of bytes actually emitted.
"""

from __future__ import annotations

import struct
import sys


def dump(path: str) -> None:
    raw = open(path, 'rb').read()
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    machine, nsec = struct.unpack_from('<HH', raw, pe + 4)
    opt_sz = struct.unpack_from('<H', raw, pe + 20)[0]
    magic = struct.unpack_from('<H', raw, pe + 24)[0]
    n_dirs = struct.unpack_from('<I', raw, pe + 24 + 108)[0]

    print(f'{path}')
    print(f'  pe_off=0x{pe:x} machine=0x{machine:04x} sections={nsec} '
          f'opt_magic=0x{magic:x}')
    print(f'  SizeOfOptionalHeader={opt_sz} (standard PE32+ is 240)')
    print(f'  NumberOfRvaAndSizes={n_dirs}')

    for label, origin in (('per SizeOfOptionalHeader', pe + 24 + opt_sz),
                          ('at the standard 240', pe + 24 + 240)):
        print(f'  section table {label} -> 0x{origin:x}')
        ok = True
        for i in range(nsec):
            sh = origin + i * 40
            name = raw[sh:sh + 8].rstrip(b'\x00')
            vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', raw, sh + 8)
            printable = all(32 <= c < 127 for c in name) and bool(name)
            ok &= printable
            print(f'    [{i}] name={name!r:<12} vaddr=0x{vaddr:06x} '
                  f'vsize=0x{vsize:06x} raw=0x{rsize:06x}@0x{rptr:06x}'
                  f'{"" if printable else "   <- not a name"}')
        print(f'    => {"plausible" if ok else "garbage"}')


if __name__ == '__main__':
    for arg in sys.argv[1:] or ['ntdll64.dll']:
        dump(arg)
        print()
