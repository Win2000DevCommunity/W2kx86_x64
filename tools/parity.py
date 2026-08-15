#!/usr/bin/env python3
"""
How much of the legacy engine the pipeline actually covers.

Answers one question honestly: if the pipeline replaced x86_x64.py today,
what would stop working? Compares registered passes against the legacy
methods, grouped by the phase each belongs to.
"""

from __future__ import annotations

import ast
import pathlib
import sys
from collections import defaultdict

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from x86x64.pipeline import REGISTRY, Phase  # noqa: E402
import x86x64.passes  # noqa: E402,F401  (registers them)

TRANSLATOR = REPO / 'x86x64' / 'translator'

#: legacy module -> the phase its work belongs to
MODULE_PHASE = {
    '_analysis': Phase.ANALYZE,
    '_encoding': Phase.TRANSLATE,
    '_frame': Phase.TRANSLATE,
    '_function': Phase.TRANSLATE,
    '_seh': Phase.TRANSLATE,
    '_iat': Phase.PLAN,
    '_healing': Phase.REPAIR,
    '_ubrt': Phase.REPAIR,
    '_misc': Phase.REPAIR,
    '_quirks_cmd': Phase.QUIRK,
    '_image': Phase.EMIT,
    'core': Phase.LOAD,
}


def legacy_weight():
    """(methods, lines) of the legacy engine, per phase."""
    methods = defaultdict(int)
    lines = defaultdict(int)
    for stem, phase in MODULE_PHASE.items():
        path = TRANSLATOR / f'{stem}.py'
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods[phase] += 1
                        lines[phase] += (m.end_lineno or m.lineno) - m.lineno + 1
    return methods, lines


def main() -> int:
    methods, lines = legacy_weight()
    ported = defaultdict(list)
    for p in REGISTRY:
        ported[p.phase].append(p.name)

    print('PIPELINE COVERAGE vs THE LEGACY ENGINE\n')
    print(f'{"phase":<12} {"legacy methods":>15} {"legacy lines":>13} '
          f'{"passes":>7}  status')
    print('-' * 78)

    total_m = total_l = covered_m = covered_l = 0
    for phase in Phase:
        m, l = methods.get(phase, 0), lines.get(phase, 0)
        n = len(ported.get(phase, []))
        total_m += m
        total_l += l
        if m == 0 and n == 0:
            continue
        if n and m == 0:
            status = 'new work, no legacy equivalent'
        elif n == 0 and m:
            status = 'NOT PORTED'
        else:
            status = 'partly ported'
            covered_m += m
            covered_l += l
        print(f'{phase.name:<12} {m:>15} {l:>13} {n:>7}  {status}')

    print('-' * 78)
    print(f'{"TOTAL":<12} {total_m:>15} {total_l:>13} {len(list(REGISTRY)):>7}')
    pct = 100 * covered_l / total_l if total_l else 0
    print(f'\nlegacy code under a phase the pipeline has any pass for: {pct:.0f}%')

    print('\nRegistered passes:')
    for phase in Phase:
        for name in sorted(ported.get(phase, [])):
            print(f'  {phase.name:<10} {name}')

    print('\nWhat the pipeline cannot do yet:')
    for phase in (Phase.TRANSLATE, Phase.REPAIR, Phase.QUIRK, Phase.LAYOUT,
                  Phase.EMIT, Phase.VERIFY):
        if not ported.get(phase) and methods.get(phase):
            print(f'  {phase.name:<10} {methods[phase]:>4} methods, '
                  f'{lines[phase]:>6} lines still only in the legacy engine')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
