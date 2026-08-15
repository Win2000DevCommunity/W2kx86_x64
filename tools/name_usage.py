#!/usr/bin/env python3
"""
Which runtime names does each translator module actually use?

Needed before splitting runtime.py further: a name used by a mixin has to stay
importable from ``runtime``, and anything that would make runtime depend on the
mixins (``main``, the batch drivers) has to move somewhere that nothing in
``runtime`` imports back.
"""

from __future__ import annotations

import ast
import pathlib
import sys
from collections import defaultdict

PKG = pathlib.Path('x86x64/translator')
RUNTIME = PKG / 'runtime.py'


def toplevel_names(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding='utf-8'))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name != '*':
                    names.add(a.asname or a.name.split('.')[0])
    return names


def referenced(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding='utf-8'))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            out.add(node.id)
        elif isinstance(node, ast.Attribute):
            base = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                out.add(base.id)
    return out


def main() -> int:
    provided = toplevel_names(RUNTIME)
    users: dict[str, set[str]] = defaultdict(set)

    for path in sorted(PKG.glob('*.py')):
        if path.name in ('runtime.py', '__init__.py'):
            continue
        for name in referenced(path) & provided:
            users[name].add(path.stem)

    watch = sys.argv[1:] or ['main', 'BatchTranslator', 'SystemBuilder']
    print('Names the mixins depend on:', len(users), 'of', len(provided), '\n')

    print('Requested names:')
    for name in watch:
        who = users.get(name)
        print(f'  {name:<28} {"used by " + ", ".join(sorted(who)) if who else "UNUSED by mixins"}')

    unused = sorted(provided - set(users))
    print(f'\nProvided but unused by any mixin ({len(unused)}):')
    for name in unused:
        print(f'  {name}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
