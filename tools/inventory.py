#!/usr/bin/env python3
"""Inventory x86_x64.py: classify every symbol so the split can be planned.

Prints a per-bucket line count so we can track the migration to zero.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
from collections import Counter, defaultdict

LEGACY = pathlib.Path('x86_x64.py')

#: Ordered rules: first match wins. (bucket, predicate on name)
METHOD_RULES = [
    ('quirks.cmd', lambda n: n.startswith('_fix_cmd') or n.startswith('_cmd_')),
    ('quirks.cmd', lambda n: '_cmd_' in n and n.startswith('_')),
    ('translate.healing', lambda n: n.startswith((
        '_pure_', '_snap_', '_repair_', '_heal_', '_relink_', '_fix_',
        '_reconcile_', '_neutralize_', '_scrub_', '_nop_', '_int3_',
        '_bridge_', '_materialize', '_validate_all_call', '_cf_repair',
        '_adjust_epilogue', '_pad_prologue'))),
    ('translate.seh', lambda n: 'seh' in n.lower() or 'scope' in n.lower()),
    ('encoding', lambda n: n.startswith(('_encode_', '_emit_', '_asm', '_normalize_x64'))),
    ('abi.frame', lambda n: 'ebp' in n.lower() or 'frameless' in n.lower()
     or 'arg' in n.lower() and n.startswith('_')),
    ('dispatch.iat', lambda n: 'iat' in n.lower() or 'import' in n.lower()
     or 'thunk' in n.lower()),
    ('image.builder', lambda n: n.startswith('_build_pe64')
     or n.startswith('_build_') and 'directory' in n
     or n in ('translate', '_finalize_code_layout', '_refresh_final_rvas',
              '_choose_translation', '_export_rva')),
    ('translate.function', lambda n: n.startswith('_translate')),
    ('ubrt', lambda n: 'ubrt' in n.lower()),
    ('analysis', lambda n: n.startswith(('_is_', '_looks_', '_find_', '_discover',
                                         '_collect', '_scan', '_x86_', '_opcode',
                                         '_out_tail', '_call_target',
                                         '_offset_is', '_entry_', '_note_',
                                         '_movabs_', '_e8_byte', '_x64_'))),
]

FUNCTION_RULES = [
    ('analysis.text', lambda n: n.startswith(('_x64_bytes_for', '_is_plausible',
                                              '_valid_x86', '_collect_x86',
                                              '_merge_spans', '_scan_x86',
                                              'analyze_x86_text'))),
    ('analysis.discover', lambda n: n.startswith('discover')),
    ('syscall', lambda n: 'syscall' in n.lower() or 'stub' in n.lower()
     or n.startswith(('set_syscall', 'get_syscall', 'resolve_', 'apply_win10',
                      'count_', 'export_syscall', 'auto_load', 'load_syscall'))),
    ('pe.fixup', lambda n: n.startswith(('fixup_', 'remap_'))),
    ('shim', lambda n: 'shim' in n.lower()),
    ('abi.frame', lambda n: n.startswith('ebp_')),
    ('dispatch.iat', lambda n: n.startswith('transform_imports')),
    ('cli', lambda n: n in ('main',)),
]


def classify(name: str, rules) -> str:
    for bucket, pred in rules:
        try:
            if pred(name):
                return bucket
        except Exception:
            pass
    return 'unclassified'


def main() -> int:
    src = LEGACY.read_text(encoding='utf-8', errors='replace')
    lines = src.splitlines()
    tree = ast.parse(src)

    buckets: Counter[str] = Counter()
    members: dict[str, list[str]] = defaultdict(list)
    total_body = 0

    def span(node) -> int:
        return (node.end_lineno or node.lineno) - node.lineno + 1

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bucket = classify(node.name, FUNCTION_RULES)
            buckets[bucket] += span(node)
            members[bucket].append(f'{node.name} ({span(node)}L)')
            total_body += span(node)
        elif isinstance(node, ast.ClassDef):
            if node.name != 'Win2000Translator':
                bucket = {'PE32Image': 'pe.pe32',
                          'StubInfo': 'syscall',
                          'DynamicScanner': 'analysis.dynamic',
                          'DynamicScanResult': 'analysis.dynamic',
                          'X86TextAnalysis': 'analysis.text',
                          'BatchTranslator': 'cli',
                          'SystemBuilder': 'cli'}.get(node.name, 'unclassified')
                buckets[bucket] += span(node)
                members[bucket].append(f'class {node.name} ({span(node)}L)')
                total_body += span(node)
                continue

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    bucket = classify(item.name, METHOD_RULES)
                    buckets[bucket] += span(item)
                    members[bucket].append(f'{item.name} ({span(item)}L)')
                    total_body += span(item)

    print(f'{LEGACY}: {len(lines)} lines total, {total_body} in defs/classes\n')
    print(f'{"bucket":<24} {"lines":>7} {"count":>6}')
    print('-' * 40)
    for bucket, count in buckets.most_common():
        print(f'{bucket:<24} {count:>7} {len(members[bucket]):>6}')
    print('-' * 40)
    print(f'{"TOTAL":<24} {total_body:>7} {sum(len(m) for m in members.values()):>6}')

    if '--detail' in sys.argv:
        target = sys.argv[sys.argv.index('--detail') + 1]
        print(f'\n{target}:')
        for m in sorted(members[target]):
            print(f'  {m}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
