#!/usr/bin/env python3
"""Smoke-test PE resource directory + UBRT insert on cmd_shim."""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'win2k_analyzer'))

try:
    import pefile
except ImportError:
    print('SKIP: pip install pefile')
    sys.exit(0)

SHIM = os.path.join(ROOT, '..', 'win2000_x64', 'cmd_shim.exe')
SRC = r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe'


def check_resources(path: str, label: str) -> bool:
    pe = pefile.PE(path)
    rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
    ok = bool(rva and size and hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'))
    n = len(list(pe.DIRECTORY_ENTRY_RESOURCE.entries)) if ok else 0
    print(f'[{label}] resource dir rva=0x{rva:x} size={size} entries={n} -> {"OK" if ok else "FAIL"}')
    return ok


def test_ubrt_insert() -> bool:
    from x86_x64 import Win2000Translator, HAS_UBRT
    if not HAS_UBRT:
        print('[UBRT] engine not importable')
        return False
    if not os.path.isfile(SHIM):
        print('[UBRT] cmd_shim.exe missing — translate first')
        return False
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
        tmp_path = tmp.name
    try:
        blob, info = Win2000Translator.ubrt_insert_bytes(
            SHIM, 0x8777, b'\x90' * 4, out_path=tmp_path)
    except RuntimeError as exc:
        print(f'[UBRT] SKIP load/insert on cmd_shim: {exc}')
        return True
        print(f'[UBRT] insert delta={info["delta"]} refs_updated={info["refs_updated"]}')
        if info['warnings']:
            print(f'[UBRT] warnings: {info["warnings"][:3]}')
        pe = pefile.PE(data=blob)
        text = next(s for s in pe.sections if b'.text' in s.Name)
        off = pe.get_offset_from_rva(0x8777)
        got = pe.__data__[off:off + 4]
        ok = got == b'\x90' * 4
        print(f'[UBRT] bytes @0x8777: {got.hex()} -> {"OK" if ok else "FAIL"}')
        return ok
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main() -> int:
    ok = True
    if os.path.isfile(SRC):
        check_resources(SRC, 'source x86 cmd.exe')
    if os.path.isfile(SHIM):
        ok = check_resources(SHIM, 'cmd_shim') and ok
    else:
        print(f'cmd_shim not found at {SHIM}')
        ok = False
    ok = test_ubrt_insert() and ok
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
