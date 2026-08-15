#!/usr/bin/env python3
"""Rewrite UTF-16 source files as UTF-8.

The editor on this machine writes new files as UTF-16LE, which CPython refuses
to import ("source code string cannot contain null bytes").  Run this over the
package after adding files.
"""

from __future__ import annotations

import pathlib
import sys

ROOTS = ('x86x64', 'tests', 'tools')


def convert(path: pathlib.Path) -> bool:
    raw = path.read_bytes()
    if b'\x00' not in raw:
        return False
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        text = raw.decode('utf-16')
    else:
        text = raw.decode('utf-16-le')
    path.write_bytes(text.encode('utf-8'))
    return True


def main(argv: list[str]) -> int:
    roots = argv[1:] or list(ROOTS)
    changed = 0
    for root in roots:
        base = pathlib.Path(root)
        paths = [base] if base.is_file() else sorted(base.rglob('*.py'))
        for path in paths:
            if convert(path):
                print(f'utf-8: {path}')
                changed += 1
    print(f'{changed} file(s) converted')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
