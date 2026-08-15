#!/usr/bin/env python3
"""
Measure how modular the package actually is.

Splitting a file is not the same as decoupling it. This reports, per module,
how much shared mutable state it touches and how much of that state other
modules also touch -- the number that decides whether a module can be
understood, tested, or replaced on its own.
"""

from __future__ import annotations

import ast
import pathlib
from collections import defaultdict
from typing import Dict, Set

PKG = pathlib.Path('x86x64')
TRANSLATOR = PKG / 'translator'
SKIP = {'runtime.py', '_env.py', '__init__.py'}


def self_attributes(path: pathlib.Path) -> tuple[Set[str], Set[str]]:
    """(attributes read or written, attributes written) via ``self.``."""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    touched: Set[str] = set()
    written: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == 'self':
            touched.add(node.attr)
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                written.add(node.attr)
    return touched, written


def method_names(path: pathlib.Path) -> Set[str]:
    tree = ast.parse(path.read_text(encoding='utf-8'))
    out: Set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.add(m.name)
    return out


def main() -> int:
    mods = sorted(p for p in TRANSLATOR.glob('*.py') if p.name not in SKIP)

    touched: Dict[str, Set[str]] = {}
    written: Dict[str, Set[str]] = {}
    methods: Dict[str, Set[str]] = {}
    for path in mods:
        touched[path.stem], written[path.stem] = self_attributes(path)
        methods[path.stem] = method_names(path)

    all_methods = set().union(*methods.values())

    # Split self.X into "calls a method" and "touches a data field".
    owners: Dict[str, Set[str]] = defaultdict(set)
    for stem, attrs in touched.items():
        for a in attrs:
            owners[a].add(stem)

    fields = {a: mods_ for a, mods_ in owners.items() if a not in all_methods}
    shared_fields = {a: m for a, m in fields.items() if len(m) > 1}

    print('SHARED MUTABLE STATE IN x86x64/translator')
    print(f'{"module":<16} {"methods":>8} {"fields":>7} {"writes":>7} '
          f'{"shared":>7}  {"% of its fields shared":>22}')
    print('-' * 78)
    for stem in sorted(methods):
        own_fields = {a for a in touched[stem] if a not in all_methods}
        own_shared = own_fields & set(shared_fields)
        pct = 100 * len(own_shared) / len(own_fields) if own_fields else 0
        print(f'{stem:<16} {len(methods[stem]):>8} {len(own_fields):>7} '
              f'{len(written[stem]):>7} {len(own_shared):>7}  {pct:>21.0f}%')

    print('-' * 78)
    print(f'{"TOTAL":<16} {len(all_methods):>8} {len(fields):>7} '
          f'{"":>7} {len(shared_fields):>7}')

    print(f'\n{len(shared_fields)} of {len(fields)} data fields are touched by '
          f'more than one module.')
    hottest = sorted(shared_fields.items(), key=lambda kv: -len(kv[1]))[:12]
    print('\nMost widely shared fields:')
    for name, users in hottest:
        print(f'  self.{name:<28} {len(users)} modules: '
              f'{", ".join(sorted(users))}')

    # Contrast: the newer subsystems, which do not share an object at all.
    print('\n\nFOR CONTRAST -- subsystems built around explicit inputs/outputs')
    print(f'{"package":<14} {"files":>6} {"lines":>7} {"classes":>8} {"self-fields":>12}')
    print('-' * 52)
    for sub in sorted(PKG.iterdir()):
        if not sub.is_dir() or sub.name == 'translator':
            continue
        files = sorted(sub.glob('*.py'))
        if not files:
            continue
        lines = sum(len(f.read_text(encoding='utf-8').splitlines()) for f in files)
        classes = 0
        fieldset: Set[str] = set()
        for f in files:
            tree = ast.parse(f.read_text(encoding='utf-8'))
            classes += sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
            t, _w = self_attributes(f)
            fieldset |= t
        print(f'{sub.name:<14} {len(files):>6} {lines:>7} {classes:>8} '
              f'{len(fieldset):>12}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
