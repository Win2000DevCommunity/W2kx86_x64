"""
Structural guarantees for the split package.

The translation passes were carved out of one 21k-line module, so the risk is
not that the logic changed -- it is that a name stopped resolving, or that two
modules started importing each other. Both fail only on the code path that
touches them, which for the address-pinned repairs can mean one specific input
binary. These tests catch that statically instead.
"""

from __future__ import annotations

import ast
import builtins
import importlib
import pathlib
import pkgutil
import subprocess
import symtable
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
PKG = REPO / 'x86x64'

#: Names bound by the interpreter rather than by any statement we can see.
IMPLICIT = {'__file__', '__name__', '__doc__', '__package__', '__spec__',
            '__loader__', '__builtins__', '__path__', '__debug__',
            '__annotations__', '__class__', '__module__', '__qualname__',
            'WindowsError'}


def module_names() -> list[str]:
    out = []
    for info in pkgutil.walk_packages([str(PKG)], prefix='x86x64.'):
        out.append(info.name)
    return sorted(out)


ALL_MODULES = module_names()


def global_refs(source: str, filename: str) -> set[str]:
    """Every name a module reads from its own global scope.

    ``symtable`` is the compiler's own scope analysis, so this correctly
    ignores locals, parameters, comprehension variables, and closures.
    """
    refs: set[str] = set()

    def walk(table: symtable.SymbolTable) -> None:
        for sym in table.get_symbols():
            if sym.is_referenced() and sym.is_global() and not sym.is_assigned():
                refs.add(sym.get_name())
        for child in table.get_children():
            walk(child)

    walk(symtable.symtable(source, filename, 'exec'))
    return refs


@pytest.mark.parametrize('modname', ALL_MODULES)
def test_module_imports_cleanly(modname):
    """Every module imports on its own, with no cycle and no missing name."""
    importlib.import_module(modname)


@pytest.mark.parametrize('modname', ALL_MODULES)
def test_module_imports_first_in_a_fresh_interpreter(modname):
    """Import it before anything else has been imported.

    Within one session the first import wins and every later one is a cache
    hit, so a cycle only shows up for whichever module happens to go first.
    That hides real breakage: importing ``x86x64.analysis.discover`` ahead of
    ``x86x64.translator`` cycled, while the same module imported after it was
    fine. A subprocess per module is the only way to see it.
    """
    proc = subprocess.run(
        [sys.executable, '-c', f'import {modname}'],
        cwd=REPO, capture_output=True, text=True, timeout=120)

    assert proc.returncode == 0, (
        f'importing {modname} first fails:\n'
        + (proc.stderr or proc.stdout).strip()[-1500:])


@pytest.mark.parametrize('modname', ALL_MODULES)
def test_every_global_reference_resolves(modname):
    """No module reads a global that nothing provides.

    This is the check that catches a name lost in the split -- for instance a
    flag assigned inside a ``try:`` block, which a generated ``__all__`` list
    silently drops.
    """
    module = importlib.import_module(modname)
    path = pathlib.Path(module.__file__)
    source = path.read_text(encoding='utf-8')

    available = set(dir(module)) | set(dir(builtins)) | IMPLICIT
    unresolved = sorted(global_refs(source, str(path)) - available)

    assert not unresolved, (
        f'{modname} reads {len(unresolved)} name(s) nothing defines: '
        + ', '.join(unresolved[:15]))


def _translator_modules() -> list[pathlib.Path]:
    return sorted(p for p in (PKG / 'translator').glob('*.py')
                  if p.name not in {'runtime.py', '_env.py', '__init__.py'})


@pytest.mark.parametrize('path', _translator_modules(), ids=lambda p: p.stem)
def test_class_qualified_calls_resolve(path):
    """A method reached through a class name must exist on the composed class.

    Splitting one class into mixins silently rebinds two things: ``__class__``
    now names the mixin instead of the whole translator, and ``Foo.bar()``
    only works while ``bar`` happens to live in ``Foo``.  Both still import
    fine and only blow up when the branch runs, which for the repair passes
    can be one specific input.
    """
    from x86x64.translator import Win2000Translator
    from x86x64 import translator as tpkg

    known = {name for name in dir(tpkg)
             if name.endswith('Mixin') or name == 'Win2000Translator'}
    known.add('__class__')

    tree = ast.parse(path.read_text(encoding='utf-8'))
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        base = node.value
        name = (base.id if isinstance(base, ast.Name) else None)
        if name not in known:
            continue
        if not hasattr(Win2000Translator, node.attr):
            bad.append(f'line {node.lineno}: {name}.{node.attr}')

    assert not bad, (f'{path.name} calls through a class name that does not '
                     f'provide it:\n  ' + '\n  '.join(bad))


@pytest.mark.parametrize('path', _translator_modules(), ids=lambda p: p.stem)
def test_no_lexical_class_references(path):
    """``__class__`` must not appear in a mixin.

    It binds to the mixin, not to :class:`Win2000Translator`, so it silently
    means something different than it did in the single-class original.
    """
    source = path.read_text(encoding='utf-8')
    hits = [i + 1 for i, line in enumerate(source.splitlines())
            if '__class__' in line]

    assert not hits, (f'{path.name} uses __class__ on line(s) '
                      f'{", ".join(map(str, hits))}; use self. instead')


def test_env_does_not_depend_on_the_passes():
    """``_env`` is the bottom of the import order and must stay there.

    Everything else may import it; if it imports back into the translator or a
    domain module, the layering collapses and cycles reappear.
    """
    source = (PKG / 'translator' / '_env.py').read_text(encoding='utf-8')
    tree = ast.parse(source)

    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or '').startswith('x86x64'):
            mod = node.module
            leaf = mod.count('.') >= 2 and 'translator' not in mod
            if not leaf:
                offenders.append(mod)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.startswith('x86x64'):
                    offenders.append(a.name)

    assert not offenders, (
        '_env.py may only import leaf data modules, but imports: '
        + ', '.join(sorted(set(offenders))))


def test_legacy_entry_point_still_works():
    """``x86_x64.py`` stays importable for scripts that predate the split."""
    import x86_x64

    assert hasattr(x86_x64, 'main')
    assert hasattr(x86_x64, 'Win2000Translator')
    assert hasattr(x86_x64, 'WIN2000_SYSCALL_TABLE')


def test_legacy_module_is_a_shim():
    """The point of the split: no logic left in the original file."""
    source = (REPO / 'x86_x64.py').read_text(encoding='utf-8')
    tree = ast.parse(source)

    defs = [n.name for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]

    assert not defs, f'x86_x64.py still defines: {", ".join(defs)}'
    assert len(source.splitlines()) < 60
