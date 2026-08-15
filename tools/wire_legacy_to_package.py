#!/usr/bin/env python3
"""Repoint the legacy translator's duplicated data tables at the package.

Replaces the inline ``WIN2000_SYSCALL_TABLE`` and ``TEB_FS_TO_GS`` literals in
``x86_x64.py`` with imports from ``x86x64``, so there is a single authority for
each.  Idempotent: running it twice is a no-op.
"""

from __future__ import annotations

import io
import pathlib
import re
import shutil

LEGACY = pathlib.Path('x86_x64.py')
BACKUP = pathlib.Path('x86_x64.py.orig')

SYSCALL_REPLACEMENT = '''# The Win2000 SSDT now lives in ``x86x64.syscall.table_data`` so the package
# and this module cannot drift apart. See tests/test_legacy_parity.py.
from x86x64.syscall import WIN2000_SYSCALL_TABLE
'''

TEB_REPLACEMENT = '''# TEB field remapping: FS:[32-bit offset] -> GS:[64-bit offset].
# Authoritative table lives in ``x86x64.abi.teb``.
from x86x64.abi import FS_TO_GS as TEB_FS_TO_GS
'''


def find_block(lines: list[str], start_pattern: str) -> tuple[int, int]:
    """Line span [start, end] of a top-level literal ending at a lone ']' or '}'."""
    start = next(i for i, line in enumerate(lines)
                 if re.match(start_pattern, line))
    closer = ']' if lines[start].rstrip().endswith('[') else '}'
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].rstrip() == closer)
    return start, end


def main() -> int:
    text = LEGACY.read_text(encoding='utf-8', errors='replace')
    lines = text.splitlines()

    if 'from x86x64.syscall import WIN2000_SYSCALL_TABLE' in text:
        print('already wired; nothing to do')
        return 0

    if not BACKUP.exists():
        shutil.copyfile(LEGACY, BACKUP)
        print(f'backed up original to {BACKUP}')

    # Work back to front so earlier line numbers stay valid.
    teb_start, teb_end = find_block(lines, r'^TEB_FS_TO_GS')
    # Include the two comment lines above the TEB table.
    while teb_start > 0 and lines[teb_start - 1].startswith('#'):
        teb_start -= 1
    lines[teb_start:teb_end + 1] = TEB_REPLACEMENT.rstrip('\n').split('\n')

    sys_start, sys_end = find_block(lines, r'^WIN2000_SYSCALL_TABLE')
    lines[sys_start:sys_end + 1] = SYSCALL_REPLACEMENT.rstrip('\n').split('\n')

    with io.open(LEGACY, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(lines) + '\n')

    removed = len(text.splitlines()) - len(lines)
    print(f'wired legacy module to the package ({removed} lines removed)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
