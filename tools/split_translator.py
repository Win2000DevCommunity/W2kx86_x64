#!/usr/bin/env python3
"""
Split x86_x64.py into the x86x64.translator package.

The 18k-line ``Win2000Translator`` is broken into domain mixins, one module
each, and the module-level imports/constants/free functions move to a shared
``runtime`` module.  Methods are copied by *line span*, not re-generated from
the AST, so comments, formatting, and blank lines survive byte-for-byte.

This is deliberately mechanical.  Correctness is checked by rebuilding a real
binary and comparing hashes; cleaning up each module's internals happens after
the structure is in place.
"""

from __future__ import annotations

import ast
import io
import pathlib
import shutil
import sys
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

LEGACY = pathlib.Path('x86_x64.py')
PKG = pathlib.Path('x86x64/translator')
TRANSLATOR_CLASS = 'Win2000Translator'

#: bucket -> (module stem, mixin class name, docstring)
BUCKETS: Dict[str, Tuple[str, str, str]] = {
    'quirks.cmd': ('_quirks_cmd', 'CmdQuirksMixin', """\
Address-pinned repairs for a specific cmd.exe build.

Every method here keys off a hard-coded x86 RVA, so none of it generalises.
It is kept isolated -- and skipped entirely in ``--pure`` mode -- because the
relocation-based pipeline in :mod:`x86x64.core` is meant to make it
unnecessary rather than to grow it."""),
    'translate.healing': ('_healing', 'HealingMixin', """\
Post-translation repair passes.

These re-derive call targets, branch destinations, and entry points after the
fact.  Most of them exist because addresses were baked into emitted bytes;
they shrink as emitters move to recording relocations instead."""),
    'translate.function': ('_function', 'FunctionTranslationMixin', """\
Instruction-level translation: x86 function bodies to x64."""),
    'translate.seh': ('_seh', 'SehMixin', """\
Structured exception handling: VC6 scope tables and handler fixups."""),
    'image.builder': ('_image', 'ImageBuilderMixin', """\
PE64 assembly: section layout, directories, and the final image."""),
    'analysis': ('_analysis', 'AnalysisMixin', """\
Predicates and searches over translated and untranslated code."""),
    'encoding': ('_encoding', 'EncodingMixin', """\
Instruction emission helpers bound to translator state."""),
    'abi.frame': ('_frame', 'FrameMixin', """\
Stack frames and argument marshalling between the two ABIs."""),
    'dispatch.iat': ('_iat', 'IatMixin', """\
Import address table dispatch and thunk construction."""),
    'ubrt': ('_ubrt', 'UbrtMixin', """\
Integration with the external UBRT shift engine."""),
    'unclassified': ('_misc', 'MiscMixin', """\
Translator methods not yet sorted into a domain module."""),
}

#: Methods that stay on the composed class itself rather than a mixin.
CORE_METHODS = {'__init__', '__repr__'}

# Reuse the inventory's classifier so both tools agree.
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from inventory import METHOD_RULES, classify  # noqa: E402


def leading_comment_start(lines: Sequence[str], first: int, indent: int) -> int:
    """Walk back over the comment block immediately above line *first*."""
    i = first
    while i > 0:
        prev = lines[i - 1]
        stripped = prev.strip()
        if stripped.startswith('#') and (len(prev) - len(prev.lstrip())) >= indent:
            i -= 1
            continue
        break
    return i


def node_span(node: ast.AST, lines: Sequence[str]) -> Tuple[int, int]:
    """0-based [start, end) covering decorators, the def, and any lead comment."""
    first = node.lineno - 1
    for dec in getattr(node, 'decorator_list', []):
        first = min(first, dec.lineno - 1)
    indent = len(lines[first]) - len(lines[first].lstrip())
    first = leading_comment_start(lines, first, indent)
    return first, node.end_lineno


def dedent_block(block: List[str], amount: int) -> List[str]:
    out = []
    for line in block:
        if not line.strip():
            out.append('')
        elif line[:amount].strip() == '':
            out.append(line[amount:])
        else:
            out.append(line.lstrip())
    return out


def main() -> int:
    src = LEGACY.read_text(encoding='utf-8', errors='replace')
    lines = src.splitlines()
    tree = ast.parse(src)

    translator = next(n for n in tree.body
                      if isinstance(n, ast.ClassDef) and n.name == TRANSLATOR_CLASS)
    tstart, tend = node_span(translator, lines)

    # -- 1. runtime: everything at module level except the translator ----
    runtime_spans: List[Tuple[int, int]] = []
    module_names: List[str] = []
    cursor = 0
    for node in tree.body:
        if node is translator:
            start, end = tstart, tend
            if cursor < start:
                runtime_spans.append((cursor, start))
            cursor = end
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_names.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    module_names.append(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            module_names.append(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    continue
                module_names.append(alias.asname or alias.name.split('.')[0])
    if cursor < len(lines):
        runtime_spans.append((cursor, len(lines)))

    runtime_body: List[str] = []
    for start, end in runtime_spans:
        runtime_body.extend(lines[start:end])

    # Drop the original module docstring; runtime.py gets its own.
    if runtime_body and runtime_body[0].startswith('#!'):
        runtime_body = runtime_body[1:]
    while runtime_body and not runtime_body[0].strip():
        runtime_body = runtime_body[1:]
    if runtime_body and runtime_body[0].lstrip().startswith('"""'):
        closing = next(i for i in range(1, len(runtime_body))
                       if runtime_body[i].rstrip().endswith('"""'))
        runtime_body = runtime_body[closing + 1:]

    seen = set()
    exported = [n for n in module_names
                if not (n in seen or seen.add(n)) and n != TRANSLATOR_CLASS]

    PKG.mkdir(parents=True, exist_ok=True)
    write_runtime(runtime_body, exported)

    # -- 2. translator methods, bucketed --------------------------------
    class_indent = None
    by_bucket: Dict[str, List[List[str]]] = defaultdict(list)
    core_parts: List[List[str]] = []
    class_prelude: List[str] = []
    counts: Dict[str, int] = defaultdict(int)

    body_cursor = None
    for item in translator.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start, end = node_span(item, lines)
            if class_indent is None:
                class_indent = len(lines[item.lineno - 1]) - \
                    len(lines[item.lineno - 1].lstrip())
                class_prelude = lines[tstart + 1:start]
            block = lines[start:end]
            if item.name in CORE_METHODS:
                core_parts.append(block)
            else:
                bucket = classify(item.name, METHOD_RULES)
                if bucket not in BUCKETS:
                    bucket = 'unclassified'
                by_bucket[bucket].append(block)
                counts[bucket] += 1
            body_cursor = end

    for bucket, blocks in sorted(by_bucket.items()):
        stem, cls, doc = BUCKETS[bucket]
        write_mixin(stem, cls, doc, blocks, class_indent)

    write_core(class_prelude, core_parts, class_indent,
               [BUCKETS[b] for b in sorted(by_bucket)])
    write_init([BUCKETS[b] for b in sorted(by_bucket)])

    total = sum(counts.values())
    print(f'runtime.py: {len(runtime_body)} lines, {len(exported)} exported names')
    for bucket in sorted(counts):
        stem, cls, _ = BUCKETS[bucket]
        print(f'{stem + ".py":<20} {cls:<26} {counts[bucket]:>4} methods')
    print(f'core.py: {len(core_parts)} method(s) kept on the class')
    print(f'{total} methods moved into {len(counts)} modules')
    return 0


HEADER = '''"""{doc}

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403
from .runtime import *  # re-exported for the method bodies below


class {cls}:
'''


def write_mixin(stem: str, cls: str, doc: str, blocks: List[List[str]],
                indent: int) -> None:
    out = io.StringIO()
    out.write(f'"""{doc}\n\nExtracted from the legacy ``x86_x64.py`` by '
              f'``tools/split_translator.py``.\n"""\n\n')
    out.write('from __future__ import annotations\n\n')
    out.write('from .runtime import *  # noqa: F401,F403\n\n\n')
    out.write(f'class {cls}:\n')
    out.write(f'    """See the module docstring."""\n\n')
    for block in blocks:
        normalised = dedent_block(block, indent)
        for line in normalised:
            out.write(('    ' + line).rstrip() + '\n' if line else '\n')
        out.write('\n')
    (PKG / f'{stem}.py').write_text(out.getvalue(), encoding='utf-8', newline='\n')


def write_runtime(body: List[str], exported: List[str]) -> None:
    out = io.StringIO()
    out.write('"""Shared module scope for the translator mixins.\n\n'
              'Holds the imports, constants, helper classes, and free functions\n'
              'the legacy ``x86_x64.py`` defined at module level. Each mixin does\n'
              '``from .runtime import *`` so the copied method bodies resolve the\n'
              'same names they always did.\n"""\n\n')
    out.write('\n'.join(body).rstrip() + '\n\n\n')
    out.write('# Explicit __all__ so ``import *`` also carries the underscore\n'
              '# names the method bodies rely on.\n')
    out.write('__all__ = [\n')
    for name in sorted(exported):
        out.write(f'    {name!r},\n')
    out.write(']\n')
    (PKG / 'runtime.py').write_text(out.getvalue(), encoding='utf-8', newline='\n')


def write_core(prelude: List[str], core_parts: List[List[str]], indent: int,
               mixins: List[Tuple[str, str, str]]) -> None:
    bases = ', '.join(cls for _stem, cls, _doc in mixins)
    out = io.StringIO()
    out.write('"""The translator itself, composed from the domain mixins.\n\n'
              'The mixins are split purely by subject matter; they all operate on\n'
              'the state this class sets up in ``__init__``.\n"""\n\n')
    out.write('from __future__ import annotations\n\n')
    out.write('from .runtime import *  # noqa: F401,F403\n')
    for stem, cls, _doc in mixins:
        out.write(f'from .{stem} import {cls}\n')
    out.write('\n\n')
    out.write(f'class Win2000Translator(\n')
    for _stem, cls, _doc in mixins:
        out.write(f'        {cls},\n')
    out.write('):\n')
    for line in dedent_block(prelude, indent):
        out.write(('    ' + line).rstrip() + '\n' if line else '\n')
    if not prelude:
        out.write('    """Win2000 PE32 to PE64 translator."""\n')
    out.write('\n')
    for block in core_parts:
        for line in dedent_block(block, indent):
            out.write(('    ' + line).rstrip() + '\n' if line else '\n')
        out.write('\n')
    (PKG / 'core.py').write_text(out.getvalue(), encoding='utf-8', newline='\n')


def write_init(mixins: List[Tuple[str, str, str]]) -> None:
    out = io.StringIO()
    out.write('"""The x86 to x64 translator, split into domain modules."""\n\n')
    out.write('from .core import Win2000Translator\n')
    for stem, cls, _doc in mixins:
        out.write(f'from .{stem} import {cls}\n')
    out.write('\n__all__ = [\n    \'Win2000Translator\',\n')
    for _stem, cls, _doc in mixins:
        out.write(f'    {cls!r},\n')
    out.write(']\n')
    (PKG / '__init__.py').write_text(out.getvalue(), encoding='utf-8', newline='\n')


if __name__ == '__main__':
    raise SystemExit(main())
