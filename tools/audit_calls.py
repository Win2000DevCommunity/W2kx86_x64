#!/usr/bin/env python3
"""
Find direct calls and jumps whose target is not a real instruction.

A ``CALL rel32`` that lands one byte inside another instruction executes
whatever the tail of that encoding happens to decode to. Nothing detects it:
the bytes are valid, the image loads, and it runs until the damage surfaces
somewhere unrelated. The only way to see it is to decode the section and ask
whether every branch target coincides with an instruction boundary.

Linear disassembly defines the boundaries. That is exact for a section the
translator emitted densely, and where it desyncs on embedded data the run of
bogus targets makes it obvious.

    python tools/audit_calls.py build_fix/cmd_pure.exe
    python tools/audit_calls.py build_fix/cmd_pure.exe --map build_fix/rva.txt
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import struct
import sys
from typing import Dict, List, Optional, Set, Tuple

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def read_text_section(blob: bytes) -> Tuple[int, bytes, int]:
    """Return ``(rva, data, image_base)`` for the first executable section."""
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    n = struct.unpack_from('<H', blob, pe + 6)[0]
    opt_sz = struct.unpack_from('<H', blob, pe + 20)[0]
    base = struct.unpack_from('<Q', blob, pe + 24 + 24)[0]
    sec = pe + 24 + opt_sz
    for i in range(n):
        off = sec + i * 40
        vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', blob, off + 8)
        flags = struct.unpack_from('<I', blob, off + 36)[0]
        if flags & 0x20000000:
            return vaddr, blob[rptr:rptr + rsize], base
    raise SystemExit('no executable section')


def load_map(path: Optional[pathlib.Path]) -> Dict[int, int]:
    if not path or not path.exists():
        return {}
    out = {}
    for line in path.read_text(errors='replace').splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[int(parts[0], 16)] = int(parts[1], 16)
            except ValueError:
                pass
    return out


def disassemble(data: bytes, base_rva: int, seeds: Optional[Set[int]] = None):
    """Linear sweep that resynchronises instead of stopping at bad bytes.

    Capstone halts at the first byte it cannot decode, which in a translated
    image happens almost immediately -- padding and embedded data sit in the
    same section as code. Skipping a byte and resuming covers the section.

    Addresses the translator recorded as instruction starts are decoded first,
    so genuine boundaries win over anything a desynchronised sweep invents.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    found: Dict[int, object] = {}
    for seed in sorted(seeds or ()):
        off = seed - base_rva
        if 0 <= off < len(data):
            for ins in md.disasm(data[off:off + 16], seed):
                found.setdefault(ins.address, ins)
                break

    off = 0
    while off < len(data):
        produced = False
        for ins in md.disasm(data[off:], base_rva + off):
            found.setdefault(ins.address, ins)
            off = ins.address - base_rva + ins.size
            produced = True
        if not produced:
            off += 1
    return [found[a] for a in sorted(found)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image')
    ap.add_argument('--map', dest='rva_map')
    ap.add_argument('--show', type=int, default=15, help='bad sites to list')
    args = ap.parse_args()

    blob = pathlib.Path(args.image).read_bytes()
    text_rva, data, image_base = read_text_section(blob)

    rmap = load_map(pathlib.Path(args.rva_map)) if args.rva_map else {}
    mapped: Set[int] = set(rmap.values())
    reverse: Dict[int, int] = {v: k for k, v in rmap.items()}

    insns = disassemble(data, text_rva, mapped)
    starts: Set[int] = {i.address for i in insns} | mapped
    text_end = text_rva + len(data)
    print(f'{args.image}: .text rva {text_rva:#x} size {len(data):#x}, '
          f'{len(insns):,} instructions decoded, {len(mapped):,} mapped starts')

    total = 0
    bad: List[Tuple] = []
    kinds = collections.Counter()
    for ins in insns:
        op = data[ins.address - text_rva]
        if op not in (0xE8, 0xE9) or ins.size != 5:
            continue
        total += 1
        rel = struct.unpack_from('<i', data, ins.address - text_rva + 1)[0]
        target = ins.address + 5 + rel
        kind = 'call' if op == 0xE8 else 'jmp'
        if target in starts:
            continue
        if not (text_rva <= target < text_end):
            kinds[f'{kind}: outside .text'] += 1
        else:
            kinds[f'{kind}: mid-instruction'] += 1
        bad.append((ins.address, kind, target))

    print(f'\ndirect call/jmp sites : {total:,}')
    print(f'bad targets           : {len(bad):,} '
          f'({100.0 * len(bad) / max(total, 1):.2f}%)')
    for k, v in sorted(kinds.items()):
        print(f'  {k:<28} {v:,}')

    if bad and args.show:
        print(f'\nfirst {min(args.show, len(bad))} bad sites:')
        print(f'{"site":>9} {"kind":<5} {"target":>9}  {"x86 site":>9} '
              f'{"intended":>9}  note')
        for addr, kind, target in bad[:args.show]:
            src86 = reverse.get(addr, 0)
            note = ''
            prev = max((s for s in starts if s < target), default=0)
            if prev:
                note = f'{target - prev} byte(s) into insn at {prev:#x}'
            print(f'{addr:>9x} {kind:<5} {target:>9x}  {src86:>9x} '
                  f'{"":>9}  {note}')

    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
