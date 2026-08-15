#!/usr/bin/env python3
"""
Split x86x64/translator/runtime.py into domain modules.

Leaves a clean layering:

    _env.py            imports, constants, tables -- no logic, depends on nothing
                       in x86x64 except leaf data modules
    <domain>/*.py      the free functions and helper classes, grouped by subject
    runtime.py         a re-export hub so the mixins keep resolving every name

Cross-module references are resolved automatically: if a function that lands in
``analysis/discover.py`` calls one that lands in ``analysis/text.py``, the
import is generated.  Bodies are copied by line span, so nothing is reformatted.
"""

from __future__ import annotations

import ast
import io
import pathlib
from collections import defaultdict
from typing import Dict, List, Sequence, Set, Tuple

RUNTIME = pathlib.Path('x86x64/translator/runtime.py')
ENV = pathlib.Path('x86x64/translator/_env.py')

#: target module -> (docstring, [symbols])
GROUPS: Dict[str, Tuple[str, List[str]]] = {
    'x86x64/analysis/text.py': ("""\
Static analysis of x86 .text: instruction boundaries, branch edges, and the
data islands that compilers leave inline.""", [
        'X86TextAnalysis',
        '_x64_bytes_for_x86_epilogue',
        '_is_plausible_x86_insn_start',
        '_valid_x86_insn_rvas',
        '_collect_x86_branch_edges',
        '_merge_spans',
        '_scan_x86_data_spans',
        'analyze_x86_text_section',
    ]),
    'x86x64/analysis/discover.py': ("""\
Function and pointer discovery.

Finds entry points, SEH anchors, jump thunks, and pointer slots that the
translator has to know about before it can move any code.""", [
        'discover_static_pointers',
        'discover_image_pointer_sites',
        '_is_nested_ebp_callee_save',
        '_is_post_chkstk_callee_save',
        '_is_batch_helper_entry',
        'discover_function_rvas',
        'discover_seh_except_handler3_push_vas',
        'discover_seh_text_targets',
        '_is_wchar16le_text_at',
        '_is_embedded_text_data_at',
        '_embedded_text_blob_size',
        'discover_push_imm_text_data_refs',
        'discover_seh_scope_anchors',
        'discover_ff25_jmp_thunks',
        '_msvc_scope_table_size',
        '_scope_table_spans',
        '_rva_inside_spans',
        'discover_crt_data_pointer_slots',
    ]),
    'x86x64/analysis/dynamic.py': ("""\
Unicorn-backed dynamic scanning, used to recover branch targets that static
analysis cannot prove.""", [
        'DynamicScanResult',
        'DynamicScanner',
    ]),
    'x86x64/syscall/legacy.py': ("""\
Syscall table lookup and NTDLL stub extraction as the legacy translator uses
them.  New code should prefer :mod:`x86x64.syscall.table`.""", [
        'set_syscall_target',
        'get_syscall_target',
        'resolve_syscall_nr',
        'apply_win10_syscall_map',
        'count_mapped_syscalls',
        'count_syscall_coverage',
        'export_syscall_table_json',
        'auto_load_win10_syscall_table',
        'resolve_win10_syscall',
        'load_syscall_table_from_ntdll',
        'StubInfo',
        'extract_stubs_from_ntdll',
        'dump_syscall_table',
    ]),
    'x86x64/pe/fixups.py': ("""\
Section-level fixups applied while moving a PE32 image to PE64 addresses.""", [
        'fixup_rsrc_section',
        'fixup_data_section',
        'remap_section_rva',
        'remap_image_va',
    ]),
    'x86x64/pe/image32.py': ("""\
The PE32 reader the legacy translator is built on.  New code should prefer
:mod:`x86x64.pe.pe32`.""", [
        'PE32Image',
    ]),
    'x86x64/dispatch/transform.py': ("""\
Rewrites a PE32 import directory into its PE64 form.""", [
        'transform_imports',
    ]),
    'x86x64/shim/builder.py': ("""\
Builds w2kshim64.dll, the compatibility DLL that backs Win2000 imports with
modern equivalents.""", [
        '_shim_asm',
        'build_w2kshim64_dll',
        'ensure_w2kshim_dll',
    ]),
    'x86x64/abi/frames.py': ("""\
EBP-relative frame arithmetic for translating stack access to the x64 ABI.""", [
        'ebp_disp_to_win64_arg',
        'ebp_disp_to_rbp_home',
        'ebp_arg_slot_to_rbp_home',
        'ebp_disp_to_rbp_stack_off',
    ]),
}

PACKAGE_DOCS = {
    'x86x64/analysis': 'Static and dynamic analysis of the input image.',
    'x86x64/shim': 'The Win2000 compatibility shim DLL.',
}

#: Small helpers that belong with the constants: everything may call these, so
#: they have to sit below the domain modules in the import order.
ENV_EXTRA = ['_pure_translator_mode']


def leading_comment_start(lines: Sequence[str], first: int) -> int:
    i = first
    while i > 0 and lines[i - 1].strip().startswith('#'):
        i -= 1
    return i


def module_path(path: str) -> str:
    return path.replace('\\', '/').removesuffix('.py').replace('/', '.')


def main() -> int:
    src = RUNTIME.read_text(encoding='utf-8')
    lines = src.splitlines()
    tree = ast.parse(src)

    # -- locate every top-level symbol -----------------------------------
    spans: Dict[str, Tuple[int, int]] = {}
    defs: Set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = node.lineno - 1
            for dec in getattr(node, 'decorator_list', []):
                start = min(start, dec.lineno - 1)
            spans[node.name] = (leading_comment_start(lines, start), node.end_lineno)
            defs.add(node.name)

    assigned = {n for _doc, names in GROUPS.values() for n in names} | set(ENV_EXTRA)
    unknown = sorted(assigned - defs)
    if unknown:
        print(f'not in runtime.py: {", ".join(unknown)}')
        return 1
    leftover = sorted(defs - assigned)
    if leftover:
        print(f'unassigned symbols, add them to GROUPS or ENV_EXTRA: '
              f'{", ".join(leftover)}')
        return 1

    owner: Dict[str, str] = {}
    for path, (_doc, names) in GROUPS.items():
        for name in names:
            owner[name] = path

    # -- env: constants, plus the few helpers everything can call --------
    env_lines: List[str] = []
    cursor = 0
    for _name, (start, end) in sorted(
            ((n, s) for n, s in spans.items() if n not in ENV_EXTRA),
            key=lambda kv: kv[1]):
        if cursor < start:
            env_lines.extend(lines[cursor:start])
        cursor = max(cursor, end)
    if cursor < len(lines):
        env_lines.extend(lines[cursor:])

    # Drop runtime's docstring and its generated __all__; _env gets its own.
    env_src = '\n'.join(env_lines)
    env_tree = ast.parse(env_src)
    env_split = env_src.splitlines()
    drop: List[Tuple[int, int]] = []
    for node in env_tree.body:
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == '__all__'
                        for t in node.targets)):
            drop.append((node.lineno - 1, node.end_lineno))
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str) and node.lineno <= 2:
            drop.append((node.lineno - 1, node.end_lineno))
    for start, end in sorted(drop, reverse=True):
        del env_split[start:end]

    write_env(env_split)

    # -- domain modules ---------------------------------------------------
    written: List[Tuple[str, List[str], int]] = []
    for path, (doc, names) in GROUPS.items():
        blocks = sorted((spans[n][0], spans[n][1], n) for n in names)
        body: List[str] = []
        for start, end, _n in blocks:
            body.extend(lines[start:end])

        # Which symbols owned by *other* groups does this module reference?
        parsed = ast.parse('\n'.join(body))
        refs = collect_refs(parsed)
        ann_only = annotation_refs(parsed)
        siblings: Dict[str, Set[str]] = defaultdict(set)
        typing_only: Dict[str, Set[str]] = defaultdict(set)
        for ref in refs:
            home = owner.get(ref)
            if not home or home == path:
                continue
            (typing_only if ref in ann_only else siblings)[home].add(ref)

        write_module(path, doc, body, siblings, typing_only)
        written.append((path, names, len(body)))

    write_packages()
    write_runtime_hub(GROUPS, leftover, spans, lines)

    total = sum(n for _p, _names, n in written)
    for path, names, count in sorted(written):
        print(f'{path:<34} {len(names):>3} symbols {count:>5} lines')
    print(f'\n_env.py       {len(env_split):>5} lines')
    print(f'moved {total} lines into {len(written)} domain modules')
    if leftover:
        print(f'left in runtime.py: {", ".join(leftover)}')
    return 0


def dedent_top(body: List[str]) -> List[str]:
    return body


def annotation_refs(tree: ast.Module) -> Set[str]:
    """Names that only ever appear in annotations.

    ``from __future__ import annotations`` makes these strings at runtime, so
    they can be imported under ``TYPE_CHECKING`` -- which is how the
    discover/dynamic cycle gets broken without touching either body.
    """
    in_ann: Set[str] = set()
    everywhere: Set[str] = set()

    def names_of(node) -> Set[str]:
        return {n.id for n in ast.walk(node)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}

    annotation_nodes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns:
                annotation_nodes.append(node.returns)
            for a in [*node.args.args, *node.args.posonlyargs,
                      *node.args.kwonlyargs, node.args.vararg, node.args.kwarg]:
                if a is not None and a.annotation is not None:
                    annotation_nodes.append(a.annotation)
        elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
            annotation_nodes.append(node.annotation)

    for node in annotation_nodes:
        in_ann |= names_of(node)

    annotated = {id(n) for node in annotation_nodes for n in ast.walk(node)}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                and id(node) not in annotated):
            everywhere.add(node.id)

    return in_ann - everywhere


def collect_refs(tree: ast.Module) -> Set[str]:
    out: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            out.add(node.id)
    return out


DYNAMIC_ALL = '''
# Computed rather than listed: several names here are bound inside ``try``
# blocks that probe for optional dependencies, and the underscore-prefixed
# constants have to travel through ``import *`` as well.
__all__ = [_n for _n in dir() if not _n.startswith('__')]
'''


def write_env(body: List[str]) -> None:
    out = io.StringIO()
    out.write('"""Shared module scope for the translator.\n\n'
              'Imports, feature flags, and the constant tables the translation\n'
              'passes read. This module deliberately contains no logic and no\n'
              'imports from the rest of :mod:`x86x64` beyond leaf data tables, so\n'
              'every other module can depend on it without creating a cycle.\n"""\n\n')
    out.write('\n'.join(body).strip() + '\n\n')
    out.write(DYNAMIC_ALL)
    ENV.write_text(out.getvalue(), encoding='utf-8', newline='\n')


def write_module(path: str, doc: str, body: List[str],
                 siblings: Dict[str, Set[str]],
                 typing_only: Dict[str, Set[str]]) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    out = io.StringIO()
    out.write(f'"""{doc}\n"""\n\n')
    out.write('from __future__ import annotations\n\n')
    out.write('from x86x64.translator._env import *  # noqa: F401,F403\n')
    for home in sorted(siblings):
        wanted = ', '.join(sorted(siblings[home]))
        out.write(f'from {module_path(home)} import {wanted}\n')
    if typing_only:
        out.write('\nfrom typing import TYPE_CHECKING\n\n')
        out.write('if TYPE_CHECKING:  # annotation-only, and importing it '
                  'eagerly would cycle\n')
        for home in sorted(typing_only):
            wanted = ', '.join(sorted(typing_only[home]))
            out.write(f'    from {module_path(home)} import {wanted}\n')
    out.write('\n\n')
    out.write('\n'.join(body).strip() + '\n')
    p.write_text(out.getvalue(), encoding='utf-8', newline='\n')


def write_packages() -> None:
    for pkg, doc in PACKAGE_DOCS.items():
        init = pathlib.Path(pkg) / '__init__.py'
        if init.exists():
            continue
        init.parent.mkdir(parents=True, exist_ok=True)
        init.write_text(f'"""{doc}\n\n'
                        'Submodules are imported directly rather than re-exported\n'
                        'here, so that low-level modules can depend on this package\n'
                        'without pulling in the translator.\n"""\n',
                        encoding='utf-8', newline='\n')


def write_runtime_hub(groups, leftover, spans, lines) -> None:
    out = io.StringIO()
    out.write('"""Name resolution hub for the translation passes.\n\n'
              'The passes were written against one flat module scope. Rather than\n'
              'rewrite every reference, each pass does ``from .runtime import *``\n'
              'and this module gathers the pieces back together from the domain\n'
              'packages they now live in.\n"""\n\n')
    out.write('from __future__ import annotations\n\n')
    out.write('from ._env import *  # noqa: F401,F403\n')
    for path, (_doc, names) in sorted(groups.items()):
        out.write(f'from {module_path(path)} import (  # noqa: F401\n')
        for name in sorted(names):
            out.write(f'    {name},\n')
        out.write(')\n')
    if leftover:
        out.write('\n\n')
        for name in leftover:
            start, end = spans[name]
            out.write('\n'.join(lines[start:end]).strip() + '\n\n')
    out.write(DYNAMIC_ALL)
    RUNTIME.write_text(out.getvalue(), encoding='utf-8', newline='\n')


if __name__ == '__main__':
    raise SystemExit(main())
