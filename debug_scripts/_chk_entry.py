#!/usr/bin/env python3
"""Probe whether find_sane / mapped_entry_sane work for the getenv callees."""
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
    print('old_base', hex(pe.image_base))
    for s in pe.sections:
        print(f"  {s['name']:8} vaddr={s['vaddr']:#x}")

    blob = EXE.read_bytes()
    trva, data, new_base = read_text_section(blob)
    print('new_base', hex(new_base), 'text_rva', hex(trva))

    for abs_rva, label in ((0x489e0, '0x640e entry'), (0x9d24, '0x6581 entry')):
        off = abs_rva - trva
        imm = struct.unpack_from('<Q', data, off + 2)[0]
        print(f'{label} @{abs_rva:#x}: opcode={data[off:off+2].hex()} imm={imm:#x}')

    t = Win2000Translator(pe, win10_test_shim=True, source_path=str(SRC))
    t.new_base = new_base
    t._cmd_no_hacks = True
    t._fn_entry_rvas = {0x640e, 0x6581}
    t._is_alloca_probe_rva = lambda r: False

    layout = {'.text': 0x1000, '.data': 0x5c000, '.rsrc': 0x6a000}
    t._old_to_new_section = {}
    for s in pe.sections:
        name = s['name'].rstrip('\0').lower()
        if name in layout:
            t._old_to_new_section[s['vaddr']] = layout[name]
    print('old_to_new', {hex(k): hex(v) for k, v in t._old_to_new_section.items()})

    rmap_abs = load_map(RMAP)
    text_rmap = {k: v - trva for k, v in rmap_abs.items() if v >= trva}
    t.rva_map = dict(text_rmap)

    sec, text_data = pe.get_text_section()
    text_rva = sec.vaddr
    out = bytearray(data)

    for va in (0x4ad22b00, 0x4ad20be6):
        print(f'relocate {va:#x} -> {t._relocate_imm(va):#x}')

    for tgt in (0x640e, 0x6581):
        mapped = text_rmap.get(tgt)
        print(f'\nx86 {tgt:#x}: mapped_off={mapped and hex(mapped)} '
              f'abs={mapped and hex(mapped + trva)}')
        if mapped is not None:
            print('  sane(mapped)?',
                  t._pure_mapped_entry_sane(out, mapped, tgt, text_data, text_rva))
        sane = t._pure_find_sane_entry_for_x86(
            out, tgt, text_rmap, text_data, text_rva)
        print(f'  find_sane -> {sane and hex(sane)} abs={sane and hex(sane + trva)}')
        if sane is not None:
            print('  sane(sane)?',
                  t._pure_mapped_entry_sane(out, sane, tgt, text_data, text_rva))
            print('  bytes', out[sane:sane + 10].hex())

    # How many call targets in the map fail mapped_entry_sane but have a sane entry?
    need = set()
    for k in (0x640e, 0x6581):
        need.add(k)
    # also pull a few more call targets from x86 text
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for ins in md.disasm(text_data, text_rva):
        if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            need.add(int(ins.op_str, 16))
        if len(need) > 200:
            break

    broken = fixed_possible = 0
    for tgt in sorted(need):
        off = text_rmap.get(tgt)
        if off is None:
            continue
        if t._pure_mapped_entry_sane(out, off, tgt, text_data, text_rva):
            continue
        broken += 1
        sane = t._pure_find_sane_entry_for_x86(
            out, tgt, text_rmap, text_data, text_rva)
        if sane is not None and sane != off:
            fixed_possible += 1
    print(f'\namong first ~200 call targets: {broken} broken maps, '
          f'{fixed_possible} recoverable via find_sane')


if __name__ == '__main__':
    main()
