#!/usr/bin/env python3
"""
Compare the PE headers of two images.

Written to find why one build loads and the next is rejected with
ERROR_BAD_EXE_FORMAT: the loader gives no reason, so the only way in is to
diff a good image against a bad one field by field.

    python tools/diff_pe.py good.exe bad.exe
"""

from __future__ import annotations

import pathlib
import struct
import sys
from typing import Dict, List, Tuple

DIR_NAMES = [
    'Export', 'Import', 'Resource', 'Exception', 'Certificate', 'BaseReloc',
    'Debug', 'Architecture', 'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport',
    'IAT', 'DelayImport', 'CLRRuntime', 'Reserved',
]


def parse(path: pathlib.Path) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    raw = path.read_bytes()
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    if raw[pe:pe + 4] != b'PE\0\0':
        raise SystemExit(f'{path}: no PE signature at {pe:#x}')

    (machine, nsec, tstamp, symtab, nsyms, opt_size,
     chars) = struct.unpack_from('<HHIIIHH', raw, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from('<H', raw, opt)[0]
    plus = magic == 0x20B

    f: Dict[str, object] = {
        'e_lfanew': pe,
        'Machine': machine,
        'NumberOfSections': nsec,
        'TimeDateStamp': tstamp,
        'SizeOfOptionalHeader': opt_size,
        'Characteristics': chars,
        'Magic': magic,
        'LinkerVersion': f'{raw[opt + 2]}.{raw[opt + 3]}',
        'SizeOfCode': struct.unpack_from('<I', raw, opt + 4)[0],
        'SizeOfInitializedData': struct.unpack_from('<I', raw, opt + 8)[0],
        'AddressOfEntryPoint': struct.unpack_from('<I', raw, opt + 16)[0],
        'BaseOfCode': struct.unpack_from('<I', raw, opt + 20)[0],
    }
    w = opt + 24
    f['ImageBase'] = struct.unpack_from('<Q' if plus else '<I', raw, w)[0]
    w += 8 if plus else 4
    (f['SectionAlignment'], f['FileAlignment']) = struct.unpack_from('<II', raw, w)
    f['MajorOSVersion'] = struct.unpack_from('<H', raw, w + 8)[0]
    f['MajorSubsystemVersion'] = struct.unpack_from('<H', raw, w + 16)[0]
    (f['SizeOfImage'], f['SizeOfHeaders'], f['CheckSum']) = \
        struct.unpack_from('<III', raw, w + 24)
    (f['Subsystem'], f['DllCharacteristics']) = struct.unpack_from('<HH', raw, w + 36)
    st = w + 40
    if plus:
        (f['SizeOfStackReserve'], f['SizeOfStackCommit'],
         f['SizeOfHeapReserve'], f['SizeOfHeapCommit']) = \
            struct.unpack_from('<QQQQ', raw, st)
        st += 32
    else:
        (f['SizeOfStackReserve'], f['SizeOfStackCommit'],
         f['SizeOfHeapReserve'], f['SizeOfHeapCommit']) = \
            struct.unpack_from('<IIII', raw, st)
        st += 16
    (f['LoaderFlags'], f['NumberOfRvaAndSizes']) = struct.unpack_from('<II', raw, st)
    dirs = st + 8
    for i, name in enumerate(DIR_NAMES):
        if dirs + i * 8 + 8 <= len(raw):
            rva, size = struct.unpack_from('<II', raw, dirs + i * 8)
            f[f'Dir.{name}'] = (rva, size)

    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        if o + 40 > len(raw):
            break
        name = raw[o:o + 8].rstrip(b'\0').decode('latin1', 'replace')
        vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', raw, o + 8)
        flags = struct.unpack_from('<I', raw, o + 36)[0]
        sections.append({'name': name, 'vsize': vsize, 'vaddr': vaddr,
                         'rsize': rsize, 'rptr': rptr, 'flags': flags})
    f['_file_size'] = len(raw)
    return f, sections


def fmt(v) -> str:
    if isinstance(v, tuple):
        return f'rva={v[0]:#x} size={v[1]:#x}'
    if isinstance(v, int) and v > 9:
        return f'{v:#x}'
    return str(v)


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    good_p, bad_p = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    good, gsec = parse(good_p)
    bad, bsec = parse(bad_p)

    print(f'GOOD {good_p}\nBAD  {bad_p}\n')
    print(f'{"field":<26} {"good":>22} {"bad":>22}')
    print('-' * 72)
    for key in good:
        if good[key] != bad.get(key):
            print(f'{key:<26} {fmt(good[key]):>22} {fmt(bad.get(key)):>22}')

    print(f'\nsections: {len(gsec)} good / {len(bsec)} bad')
    print(f'{"name":<10} {"vaddr":>10} {"vsize":>10} {"rptr":>10} '
          f'{"rsize":>10} {"flags":>12}')
    for label, secs in (('GOOD', gsec), ('BAD', bsec)):
        print(f'-- {label}')
        for s in secs:
            print(f'{s["name"]:<10} {s["vaddr"]:>10x} {s["vsize"]:>10x} '
                  f'{s["rptr"]:>10x} {s["rsize"]:>10x} {s["flags"]:>12x}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
