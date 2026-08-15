"""Symbol table semantics: definition, duplication, imports, merging."""

import pytest

from x86x64.core import Symbol, SymbolKind, SymbolTable, import_symbol_name
from x86x64.errors import DuplicateSymbolError, UndefinedSymbolError


class TestSymbol:
    def test_section_symbol_requires_section(self):
        with pytest.raises(ValueError, match='must name a section'):
            Symbol('foo', SymbolKind.GLOBAL)

    def test_absolute_symbol_needs_no_section(self):
        sym = Symbol('PAGE_SIZE', SymbolKind.ABSOLUTE, value=0x1000)
        assert sym.value == 0x1000
        assert sym.section is None
        assert sym.is_defined

    def test_import_symbol_requires_dll_and_name(self):
        with pytest.raises(ValueError, match='needs both dll and import_name'):
            Symbol('__imp_x', SymbolKind.IMPORT)

    def test_undefined_symbol_is_not_defined(self):
        assert not Symbol('missing', SymbolKind.UNDEFINED).is_defined

    def test_str_forms_are_distinguishable(self):
        assert str(Symbol('a', SymbolKind.ABSOLUTE, value=5)) == 'a=0x5'
        assert str(Symbol('b', SymbolKind.GLOBAL, section='.text', value=0x10)) \
            == 'b@.text+0x10'
        assert str(Symbol('c', SymbolKind.UNDEFINED)) == 'c(undef)'


class TestImportNaming:
    @pytest.mark.parametrize('dll,func,expected', [
        ('kernel32.dll', 'GetProcAddress', '__imp_kernel32!GetProcAddress'),
        ('KERNEL32.DLL', 'GetProcAddress', '__imp_kernel32!GetProcAddress'),
        ('msvcrt', 'setlocale', '__imp_msvcrt!setlocale'),
    ])
    def test_canonical_name(self, dll, func, expected):
        assert import_symbol_name(dll, func) == expected

    def test_dll_case_folds_but_function_case_is_kept(self):
        assert import_symbol_name('NTDLL.dll', 'RtlAllocateHeap') \
            == '__imp_ntdll!RtlAllocateHeap'


class TestSymbolTable:
    def test_define_and_require(self):
        t = SymbolTable('obj')
        t.at('main', '.text', 0x20)
        assert t.require('main').value == 0x20

    def test_require_unknown_raises(self):
        with pytest.raises(UndefinedSymbolError, match='nope'):
            SymbolTable().require('nope')

    def test_require_declared_but_undefined_raises(self):
        t = SymbolTable()
        t.declare('later')
        with pytest.raises(UndefinedSymbolError):
            t.require('later')

    def test_declare_then_define_resolves(self):
        t = SymbolTable()
        t.declare('later')
        t.at('later', '.text', 8)
        assert t.require('later').value == 8

    def test_conflicting_redefinition_raises(self):
        t = SymbolTable('obj')
        t.at('dup', '.text', 0)
        with pytest.raises(DuplicateSymbolError, match='dup'):
            t.at('dup', '.text', 0x100)

    def test_identical_redefinition_is_tolerated(self):
        t = SymbolTable('obj')
        t.at('same', '.text', 4)
        t.at('same', '.text', 4)
        assert len(t) == 1

    def test_declare_is_idempotent(self):
        t = SymbolTable()
        first = t.declare('x')
        assert t.declare('x') is first

    def test_partitions(self):
        t = SymbolTable()
        t.at('g', '.text', 0)
        t.absolute('a', 7)
        t.declare('u')
        t.define(Symbol('__imp_k!F', SymbolKind.IMPORT, dll='k.dll', import_name='F'))
        assert {s.name for s in t.undefined()} == {'u'}
        assert {s.name for s in t.imports()} == {'__imp_k!F'}
        assert {s.name for s in t.defined()} == {'g', 'a', '__imp_k!F'}

    def test_merge_brings_in_other_symbols(self):
        a, b = SymbolTable('a'), SymbolTable('b')
        a.at('one', '.text', 0)
        b.at('two', '.text', 0x10)
        a.merge(b)
        assert a.require('two').value == 0x10

    def test_merge_conflicting_globals_raises(self):
        a, b = SymbolTable('a'), SymbolTable('b')
        a.at('clash', '.text', 0)
        b.at('clash', '.text', 0x40)
        with pytest.raises(DuplicateSymbolError):
            a.merge(b)

    def test_merge_tolerates_local_collisions(self):
        a, b = SymbolTable('a'), SymbolTable('b')
        a.at('loop', '.text', 0, SymbolKind.LOCAL)
        b.at('loop', '.text', 0x80, SymbolKind.LOCAL)
        a.merge(b)
        assert a.require('loop').value == 0
