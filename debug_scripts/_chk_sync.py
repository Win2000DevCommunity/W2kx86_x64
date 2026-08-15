#!/usr/bin/env python3
"""Simulate authoritative x86 CALL sync for the getenv call sites."""
from __future__ import annotations

import os
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ['PURE'] = '1'

from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator
from tools.audit_calls import load_map, read_text_section

SRC = pathlib.Path(
    r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
EXE = pathlib.Path('build_fix2/cmd_pure.exe')
RMAP = pathlib.Path('build_fix2/rva.txt')


def main() -> None:
    pe = PE32Image(SRC.read_bytes())
    blob_pe = EXE.read_bytes()
    trva, data, new_base = read_text_section(blob_pe)
    out = bytearray(data)

    t = Win2000Translator(pe, win10_test_shim=True, source_path=str(SRC))
    t.new_base = new_base
    t._cmd_no_hacks = True
    t._is_alloca_probe_rva = lambda r: False
    layout = {'.text': 0x1000, '.data': 0x5c000, '.rsrc': 0x6a000}
    t._old_to_new_section = {}
    for s in pe.sections:
        name = s['name'].rstrip('\0').lower()
        if name in layout:
            t._old_to_new_section[s['vaddr']] = layout[name]

    # During heal, rva_map holds blob offsets. Convert from dumped absolute RVAs.
    rmap_abs = load_map(RMAP)
    text_rmap = {k: v - trva for k, v in rmap_abs.items() if v >= trva}
    t.rva_map = dict(text_rmap)

    sec, text_data = pe.get_text_section()
    text_rva = sec.vaddr

    # Show what sync would do for the two x86 calls around getenv.
    for x86_off in (0xab55 - text_rva, 0xab64 - text_rva):
        x86_rva = text_rva + x86_off
        rel = struct.unpack_from('<i', text_data, x86_off + 1)[0]
        tgt_x86 = (x86_rva + 5 + rel) & 0xFFFFFFFF
        print(f'\nx86 call @{x86_rva:#x} -> {tgt_x86:#x}')
        new_tgt = t._pure_find_sane_entry_for_x86(
            out, tgt_x86, text_rmap, text_data, text_rva)
        print(f'  find_sane={new_tgt and hex(new_tgt)} abs={new_tgt and hex(new_tgt+trva)}')

        anchor = None
        for delta in range(0, 12):
            for key in ((x86_rva - delta) & 0xFFFFFFFF,
                        (x86_rva + delta) & 0xFFFFFFFF):
                cand = text_rmap.get(key)
                if cand is not None:
                    anchor = cand
                    print(f'  anchor from x86 {key:#x} -> off {anchor:#x} abs {anchor+trva:#x}')
                    break
            if anchor is not None:
                break

        pro, epi = t._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        j_lo = max(0, anchor - 8)
        j_hi = min(len(out) - pl - el - 5, anchor + 96)
        print(f'  scan window [{j_lo:#x},{j_hi:#x}]')
        hits = []
        for scan in range(j_lo, j_hi):
            if out[scan:scan + pl] != pro:
                continue
            j = scan + pl
            if out[j] != 0xE8:
                continue
            if out[j + 5:j + 5 + el] != epi:
                continue
            cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
            hits.append((j, cur))
            print(f'  stub E8 @{j:#x} (abs {j+trva:#x}) cur_tgt={cur:#x} '
                  f'(abs {cur+trva:#x}) want={new_tgt and hex(new_tgt)}')
        if not hits:
            print('  NO align-stub E8 found near anchor')

    # Apply full sync and re-check the getenv site.
    before = out[0x130e7 - trva:0x130e7 - trva + 5]
    n = t._pure_authoritative_x86_call_sync(out, text_rmap, text_data, text_rva)
    after = out[0x130e7 - trva:0x130e7 - trva + 5]
    cur = 0x130e7 + 5 + struct.unpack_from('<i', out, 0x130e7 - trva + 1)[0]
    print(f'\nsync fixed {n} sites')
    print(f'call @0x130e7: before={before.hex()} after={after.hex()} -> {cur:#x}')

    # Count remaining bad targets after sync-only repair.
    from tools.audit_calls import disassemble
    mapped = set(text_rmap.values())
    # rewrite absolute starts for disasm seed
    seeds = {off + trva for off in mapped}
    # work on absolute addresses in a fake buffer view: easier to scan offsets
    insns = disassemble(bytes(out), 0, mapped)
    starts = {i.address for i in insns} | mapped
    bad = 0
    for ins in insns:
        off = ins.address
        if out[off] != 0xE8 or ins.size != 5:
            continue
        rel = struct.unpack_from('<i', out, off + 1)[0]
        tgt = off + 5 + rel
        if 0 <= tgt < len(out) and tgt not in starts:
            bad += 1
    print(f'bad mid-insn call targets after sync: {bad}')


if __name__ == '__main__':
    main()
