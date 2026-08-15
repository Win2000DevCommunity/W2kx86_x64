#!/usr/bin/env python3
"""
Move top-level symbols between modules, preserving source text exactly.

Used to peel domain groups out of ``x86x64/translator/runtime.py``.  Like the
class splitter, this copies by line span so comments and formatting survive.

    python tools/move_symbols.py --from x86x64/translator/runtime.py \\
        --to x86x64/cli/driver.py --doc "Command line entry points." \\
        --imports "from x86x64.translator import Win2000Translator" \\
        main BatchTranslator SystemBuilder

By default the source module keeps a re-export so existing star-imports still
resolve; pass --no-reexport when the move is meant to break an import cycle.
"""

from __future__ import annotations

import argparse
import ast
import io
import pathlib
from typing import Dict, List, Sequence, Tuple


def leading_comment_start(lines: Sequence[str], first: int) -> int:
    i = first
    while i > 0 and lines[i - 1].strip().startswith('#'):
        i -= 1
    return i


def top_level_spans(src: str) -> Dict[str, Tuple[int, int]]:
    """name -> 0-based [start, end) line span, decorators and comments included."""
    lines = src.splitlines()
    tree = ast.parse(src)
    spans: Dict[str, Tuple[int, int]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = node.lineno - 1
            for dec in getattr(node, 'decorator_list', []):
                start = min(start, dec.lineno - 1)
            spans[node.name] = (leading_comment_start(lines, start), node.end_lineno)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    spans[t.id] = (leading_comment_start(lines, node.lineno - 1),
                                   node.end_lineno)
    return spans


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('names', nargs='+')
    ap.add_argument('--from', dest='src', required=True)
    ap.add_argument('--to', dest='dst', required=True)
    ap.add_argument('--doc', default='')
    ap.add_argument('--imports', default='',
                    help='semicolon-separated import lines for the new module')
    ap.add_argument('--no-reexport', action='store_true')
    args = ap.parse_args()

    src_path = pathlib.Path(args.src)
    dst_path = pathlib.Path(args.dst)
    src = src_path.read_text(encoding='utf-8')
    lines = src.splitlines()
    spans = top_level_spans(src)

    missing = [n for n in args.names if n not in spans]
    if missing:
        print(f'not found in {src_path}: {", ".join(missing)}')
        return 1

    chosen = sorted(((spans[n][0], spans[n][1], n) for n in args.names))
    moved: List[str] = []
    for start, end, _name in chosen:
        moved.extend(lines[start:end])

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    out = io.StringIO()
    out.write(f'"""{args.doc or "Moved out of the legacy module."}\n"""\n\n')
    out.write('from __future__ import annotations\n\n')
    out.write('from x86x64.translator.runtime import *  # noqa: F401,F403\n')
    for line in filter(None, (s.strip() for s in args.imports.split(';'))):
        out.write(line + '\n')
    out.write('\n\n')
    out.write('\n'.join(moved).strip() + '\n\n\n')
    out.write('__all__ = [\n')
    for name in sorted(args.names):
        out.write(f'    {name!r},\n')
    out.write(']\n')
    dst_path.write_text(out.getvalue(), encoding='utf-8', newline='\n')

    # Remove from the source, back to front so earlier spans stay valid.
    keep = list(lines)
    for start, end, _name in sorted(chosen, reverse=True):
        del keep[start:end]
    new_src = '\n'.join(keep).rstrip() + '\n'

    if args.no_reexport:
        # Drop the moved names from __all__ too, or star-import breaks.
        tree = ast.parse(new_src)
        keep2 = new_src.splitlines()
        for node in tree.body:
            if (isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == '__all__'
                            for t in node.targets)):
                block = keep2[node.lineno - 1:node.end_lineno]
                block = [b for b in block
                         if not any(f'{n!r}' == b.strip().rstrip(',')
                                    for n in args.names)]
                keep2[node.lineno - 1:node.end_lineno] = block
                break
        new_src = '\n'.join(keep2).rstrip() + '\n'
    else:
        module = str(dst_path.with_suffix('')).replace('\\', '/').replace('/', '.')
        new_src += (f'\nfrom {module} import '
                    f'{", ".join(sorted(args.names))}  # noqa: E402,F401\n')

    src_path.write_text(new_src, encoding='utf-8', newline='\n')
    print(f'moved {len(args.names)} symbol(s), {len(moved)} lines: '
          f'{src_path} -> {dst_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
