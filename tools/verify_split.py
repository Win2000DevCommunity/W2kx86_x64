#!/usr/bin/env python3
"""
Prove the split preserved the translator exactly.

For a mechanical refactor, comparing method source text is a stronger check
than rebuilding: it shows every method survived, that none changed, and that
the composed class exposes the same surface. Run this before spending five
minutes on a real build.

Compares ``x86_x64.py.orig`` (pre-split) against the composed
``x86x64.translator.Win2000Translator``.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import sys
import textwrap
from typing import Dict, Tuple

ORIGINAL = pathlib.Path('x86_x64.py.presplit')
TRANSLATOR_CLASS = 'Win2000Translator'

#: The only methods allowed to differ, and why.  Each one reached a static
#: method through a class name that no longer means what it did when the whole
#: translator was a single class.
EXPECTED_EDITS = {
    '_pe_rva_byte':
        'called PETranslator._pe_rva_bytes -- a class that never existed, so '
        'this raised NameError on every call; now MiscMixin',
    '_pure_mapping_is_swallowed_slot':
        'Win2000Translator._pure_is_corrupt_x86_hybrid -> HealingMixin',
    '_e8_byte_is_real_call':
        'Win2000Translator._pure_off_in_movabs_imm -> HealingMixin',
    # __class__ binds to the lexically enclosing class, which is now the mixin
    # rather than the whole translator.  self. resolves through the real MRO.
    '_pure_mapped_entry_sane':
        '__class__._opcode_class -> self._opcode_class',
    '_validate_all_call_targets':
        '__class__._x64_entry_prologue_ok -> self._x64_entry_prologue_ok',
    '_materialize_missing_functions':
        '__class__._x64_entry_prologue_ok -> self._x64_entry_prologue_ok',
}

# Running as a script puts tools/ on the path, not the repo root.
_REPO = pathlib.Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


def original_methods(path: pathlib.Path) -> Dict[str, str]:
    """Method name -> normalised source, straight from the original file."""
    src = path.read_text(encoding='utf-8', errors='replace')
    lines = src.splitlines()
    tree = ast.parse(src)
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == TRANSLATOR_CLASS)

    out: Dict[str, str] = {}
    for item in cls.body:
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = item.lineno - 1
        for dec in item.decorator_list:
            start = min(start, dec.lineno - 1)
        block = '\n'.join(lines[start:item.end_lineno])
        out[item.name] = textwrap.dedent(block).rstrip()
    return out


def composed_methods() -> Dict[str, str]:
    """Method name -> normalised source, from the live composed class."""
    from x86x64.translator import Win2000Translator

    out: Dict[str, str] = {}
    for name in dir(Win2000Translator):
        attr = inspect.getattr_static(Win2000Translator, name)
        target = attr
        if isinstance(attr, (staticmethod, classmethod)):
            target = attr.__func__
        elif isinstance(attr, property):
            target = attr.fget
        if not (inspect.isfunction(target) or inspect.ismethod(target)):
            continue
        if getattr(target, '__module__', '').startswith('x86x64.translator'):
            try:
                out[name] = textwrap.dedent(inspect.getsource(attr)).rstrip()
            except (OSError, TypeError):
                pass
    return out


def main() -> int:
    if not ORIGINAL.exists():
        print(f'{ORIGINAL} missing -- nothing to compare against')
        return 1

    before = original_methods(ORIGINAL)
    after = composed_methods()

    missing = sorted(set(before) - set(after))
    added = sorted(set(after) - set(before))
    differing = [n for n in sorted(set(before) & set(after))
                 if before[n] != after[n]]
    expected = [n for n in differing if n in EXPECTED_EDITS]
    changed = [n for n in differing if n not in EXPECTED_EDITS]

    print(f'original : {len(before)} methods')
    print(f'composed : {len(after)} methods')

    if expected:
        print(f'\nintentionally edited ({len(expected)}):')
        for name in expected:
            print(f'  {name}\n      {EXPECTED_EDITS[name]}')
    unused = sorted(set(EXPECTED_EDITS) - set(expected))
    if unused:
        print(f'\nallowlisted but identical, drop from EXPECTED_EDITS: '
              f'{", ".join(unused)}')

    ok = True
    if missing:
        ok = False
        print(f'\nMISSING ({len(missing)}) -- lost in the split:')
        for name in missing[:40]:
            print(f'  {name}')
        if len(missing) > 40:
            print(f'  ... and {len(missing) - 40} more')
    if added:
        print(f'\nADDED ({len(added)}):')
        for name in added[:20]:
            print(f'  {name}')
    if changed:
        ok = False
        print(f'\nUNEXPECTED CHANGES ({len(changed)}):')
        for name in changed[:20]:
            print(f'  {name}')
            a, b = before[name].splitlines(), after[name].splitlines()
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    print(f'      line {i}: {x!r}')
                    print(f'         ->   {y!r}')
                    break
            if len(a) != len(b):
                print(f'      length {len(a)} -> {len(b)}')

    print('\n' + (f'all {len(before)} methods accounted for '
                  f'({len(expected)} deliberately edited, rest byte-identical)'
                  if ok else 'SPLIT IS NOT FAITHFUL'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
