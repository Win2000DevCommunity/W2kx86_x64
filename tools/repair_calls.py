#!/usr/bin/env python3
"""
Retarget direct calls that land inside an instruction.

Stale entry mappings leave ``CALL rel32`` pointing a few bytes short of the
function it meant to reach, which puts it in the tail of the previous
function -- usually mid-epilogue, sometimes mid-encoding. Both execute; both
unwind a frame that was never pushed.

The recovery does not trust the map. A function entry is the instruction that
follows a return or a run of padding, so scanning forward from the broken
target to the next such boundary finds the callee the call was reaching for.
Anything further away than ``--window`` bytes is left alone: a wrong guess is
worse than a known-bad target that a later pass can still recognise.

    python tools/repair_calls.py in.exe out.exe
    python tools/repair_calls.py in.exe out.exe --dry-run
"""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys
from typing import Dict, List, Optional, Set

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.audit_calls import (disassemble, load_map,  # noqa: E402
                               read_text_section)

#: Instructions after which the next byte begins a new function.
TERMINATORS = {'ret', 'retf', 'jmp', 'int3', 'ud2'}
PADDING = {0xCC, 0x90, 0x00}


def section_offsets(blob: bytes):
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    n = struct.unpack_from('<H', blob, pe + 6)[0]
    opt_sz = struct.unpack_from('<H', blob, pe + 20)[0]
    sec = pe + 24 + opt_sz
    for i in range(n):
        off = sec + i * 40
        flags = struct.unpack_from('<I', blob, off + 36)[0]
        if flags & 0x20000000:
            rptr = struct.unpack_from('<I', blob, off + 20)[0]
            return rptr
    raise SystemExit('no executable section')


def find_entry_after(target: int, ordered: List, index: Dict[int, int],
                     window: int) -> Optional[int]:
    """First address at or after ``target`` that starts a function."""
    lo, hi = 0, len(ordered)
    while lo < hi:                       # first instruction at/after target
        mid = (lo + hi) // 2
        if ordered[mid].address < target:
            lo = mid + 1
        else:
            hi = mid
    pos = lo
    while pos < len(ordered) and ordered[pos].address - target <= window:
        addr = ordered[pos].address
        prev = ordered[pos - 1] if pos else None
        if prev is not None and prev.mnemonic in TERMINATORS:
            return addr
        pos += 1
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image')
    ap.add_argument('output', nargs='?')
    ap.add_argument('--map', dest='rva_map')
    ap.add_argument('--window', type=int, default=64)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    blob = bytearray(pathlib.Path(args.image).read_bytes())
    text_rva, data, _base = read_text_section(bytes(blob))
    raw_off = section_offsets(bytes(blob))
    mapped: Set[int] = set(load_map(pathlib.Path(args.rva_map)).values()) \
        if args.rva_map else set()

    insns = disassemble(data, text_rva, mapped)
    ordered = insns
    index = {ins.address: i for i, ins in enumerate(ordered)}
    starts: Set[int] = set(index) | mapped

    fixed = skipped = 0
    for ins in ordered:
        rel_off = ins.address - text_rva
        if data[rel_off] != 0xE8 or ins.size != 5:
            continue
        rel = struct.unpack_from('<i', data, rel_off + 1)[0]
        target = ins.address + 5 + rel
        if target in starts:
            continue
        entry = find_entry_after(target, ordered, index, args.window)
        if entry is None:
            skipped += 1
            continue
        new_rel = entry - (ins.address + 5)
        if not (-0x80000000 <= new_rel < 0x80000000):
            skipped += 1
            continue
        if not args.dry_run:
            struct.pack_into('<i', blob, raw_off + rel_off + 1, new_rel)
        fixed += 1
        if fixed <= 12:
            print(f'  {ins.address:#08x}: {target:#08x} -> {entry:#08x} '
                  f'(+{entry - target})')

    print(f'\nretargeted {fixed} call(s), left {skipped} alone')
    if args.output and not args.dry_run:
        pathlib.Path(args.output).write_bytes(bytes(blob))
        print(f'wrote {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
