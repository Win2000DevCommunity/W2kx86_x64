#!/usr/bin/env python3
"""
Put back the class-level constants the method splitter dropped.

``split_translator.py`` moved methods but only kept class-body statements that
appeared before the first method, so nine constants defined further down the
21k-line class body were lost. Each one goes to the mixin that reads it, or to
the composed class when more than one mixin does.
"""

from __future__ import annotations

import ast
import pathlib
import re
from collections import defaultdict
from typing import Dict, List, Tuple

ORIGINAL = pathlib.Path('x86_x64.py.presplit')
PKG = pathlib.Path('x86x64/translator')
CORE = PKG / 'core.py'
SKIP = {'runtime.py', '_env.py', '__init__.py'}

#: mixin module stem -> class name, read back from the generated source.
def mixin_classes() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for path in PKG.glob('*.py'):
        if path.name in SKIP:
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                out[path.name] = node.name
                break
    return out


def dropped_attributes() -> List[Tuple[str, str]]:
    """(name, source text) for every class-level constant below the first method."""
    src = ORIGINAL.read_text(encoding='utf-8')
    lines = src.splitlines()
    tree = ast.parse(src)
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == 'Win2000Translator')
    first_method = min(m.lineno for m in cls.body
                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)))

    out: List[Tuple[str, str]] = []
    for item in cls.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if item.lineno < first_method:
            continue  # the docstring, already kept
        if isinstance(item, ast.Assign):
            names = [t.id for t in item.targets if isinstance(t, ast.Name)]
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            names = [item.target.id]
        else:
            continue
        if not names:
            continue
        start = item.lineno - 1
        while start > 0 and lines[start - 1].strip().startswith('#'):
            start -= 1
        out.append((names[0], '\n'.join(lines[start:item.end_lineno])))
    return out


def main() -> int:
    classes = mixin_classes()
    attrs = dropped_attributes()

    sources = {name: (PKG / name).read_text(encoding='utf-8')
               for name in classes}

    placement: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for name, text in attrs:
        users = [f for f, src in sources.items()
                 if re.search(rf'\b{re.escape(name)}\b', src)]
        target = users[0] if len(users) == 1 else 'core.py'
        placement[target].append((name, text))
        where = classes.get(target, 'Win2000Translator')
        print(f'{name:<24} -> {where:<26} '
              f'(read by {", ".join(sorted(users)) or "nothing"})')

    for target, items in placement.items():
        path = CORE if target == 'core.py' else PKG / target
        src = path.read_text(encoding='utf-8')
        tree = ast.parse(src)
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
        lines = src.splitlines()

        # Insert just after the class docstring, before the first method.
        anchor = cls.body[0]
        insert_at = (anchor.end_lineno
                     if isinstance(anchor, ast.Expr)
                     and isinstance(anchor.value, ast.Constant)
                     else cls.lineno)

        block: List[str] = ['']
        for _name, text in items:
            block.extend(text.splitlines())
            block.append('')
        lines[insert_at:insert_at] = block
        path.write_text('\n'.join(lines).rstrip() + '\n',
                        encoding='utf-8', newline='\n')
        print(f'  {path}: +{len(block)} lines')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
