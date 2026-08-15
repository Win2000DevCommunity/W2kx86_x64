"""Import dispatch: IAT slots resolved by the linker rather than by hand."""

import struct

import pytest

from x86x64.core import Linker, ObjectFile, SectionFlags
from x86x64.dispatch import (
    ImportTable,
    build_import_directory,
    emit_import_call,
    emit_import_fn_load,
    emit_import_jmp,
    emit_import_ptr_load,
)

BASE = 0x8000_0000


@pytest.fixture
def obj():
    o = ObjectFile('imports.obj')
    o.section('.text', SectionFlags.text())
    return o


@pytest.fixture
def imports(obj):
    return ImportTable(obj)


class TestImportTable:
    def test_declare_returns_a_ref(self, imports):
        ref = imports.declare('kernel32.dll', 'GetProcAddress')
        assert ref.dll == 'kernel32.dll'
        assert ref.symbol == '__imp_kernel32!GetProcAddress'

    def test_declaring_twice_reuses_one_ref(self, imports):
        a = imports.declare('kernel32.dll', 'GetProcAddress')
        b = imports.declare('kernel32.dll', 'GetProcAddress')
        assert a is b and len(imports) == 1

    def test_renames_apply_to_missing_x64_imports(self, imports):
        ref = imports.declare('msvcrt.dll', '_controlfp')
        assert ref.name == '_control87'

    def test_x86_slot_lookup(self, imports):
        imports.declare('msvcrt.dll', 'setlocale', x86_slot_va=0x4072C8)
        assert imports.symbol_for_x86_slot(0x4072C8) == '__imp_msvcrt!setlocale'
        assert imports.is_import_slot(0x4072C8)

    def test_unknown_slot_returns_none(self, imports):
        assert imports.symbol_for_x86_slot(0xDEAD) is None

    def test_grouping_by_dll(self, imports):
        imports.declare('kernel32.dll', 'GetProcAddress')
        imports.declare('kernel32.dll', 'GetModuleHandleW')
        imports.declare('msvcrt.dll', 'setlocale')
        grouped = imports.by_dll()
        assert len(grouped['kernel32.dll']) == 2
        assert len(grouped['msvcrt.dll']) == 1

    def test_group_members_are_sorted(self, imports):
        imports.declare('kernel32.dll', 'WriteFile')
        imports.declare('kernel32.dll', 'CloseHandle')
        names = [r.name for r in imports.by_dll()['kernel32.dll']]
        assert names == sorted(names)


class TestCallSites:
    def _link(self, obj):
        return Linker(image_base=BASE).add_object(obj).link()

    def test_call_resolves_to_the_iat_slot(self, obj, imports):
        ref = imports.declare('msvcrt.dll', 'setlocale')
        text = obj.get_section('.text')
        site = emit_import_call(text, ref.symbol)

        result = self._link(obj)
        text_va = BASE + result.layout.rva_of('.text')
        disp = struct.unpack_from('<i', result.section_bytes('.text'), site + 2)[0]
        # rip points past the 6-byte instruction
        assert text_va + site + 6 + disp == result.iat_slots[ref.symbol]

    def test_jmp_thunk_resolves_to_the_same_slot(self, obj, imports):
        ref = imports.declare('msvcrt.dll', 'setlocale')
        text = obj.get_section('.text')
        site = emit_import_jmp(text, ref.symbol)

        result = self._link(obj)
        text_va = BASE + result.layout.rva_of('.text')
        disp = struct.unpack_from('<i', result.section_bytes('.text'), site + 2)[0]
        assert text_va + site + 6 + disp == result.iat_slots[ref.symbol]

    def test_ptr_load_yields_the_slot_address(self, obj, imports):
        ref = imports.declare('kernel32.dll', 'GetProcAddress')
        text = obj.get_section('.text')
        site = emit_import_ptr_load(text, 'rax', ref.symbol)

        result = self._link(obj)
        imm = struct.unpack_from('<Q', result.section_bytes('.text'), site + 2)[0]
        assert imm == result.iat_slots[ref.symbol]

    def test_fn_load_is_rip_relative(self, obj, imports):
        ref = imports.declare('kernel32.dll', 'GetProcAddress')
        text = obj.get_section('.text')
        site = emit_import_fn_load(text, 'rax', ref.symbol)

        result = self._link(obj)
        text_va = BASE + result.layout.rva_of('.text')
        disp = struct.unpack_from('<i', result.section_bytes('.text'), site + 3)[0]
        assert text_va + site + 7 + disp == result.iat_slots[ref.symbol]

    def test_call_sites_survive_code_growth(self, imports):
        """The property the hand-computed displacements kept losing."""
        def build(padding):
            o = ObjectFile('t.obj')
            text = o.section('.text', SectionFlags.text())
            tbl = ImportTable(o)
            ref = tbl.declare('msvcrt.dll', 'setlocale')
            text.emit(b'\x90' * padding)
            o.define('site', '.text', text.tell())
            emit_import_call(text, ref.symbol)
            return o, ref

        for padding in (0, 0x100, 0x4000):
            o, ref = build(padding)
            result = Linker(image_base=BASE).add_object(o).link()
            site = result.rva_of('site') - result.layout.rva_of('.text')
            text_va = BASE + result.layout.rva_of('.text')
            disp = struct.unpack_from('<i', result.section_bytes('.text'),
                                      site + 2)[0]
            assert text_va + site + 6 + disp == result.iat_slots[ref.symbol]


class TestImportDirectory:
    def test_descriptor_count_matches_dll_count(self, imports):
        imports.declare('kernel32.dll', 'GetProcAddress')
        imports.declare('msvcrt.dll', 'setlocale')
        blob, _ = build_import_directory(imports.refs, iat_rva={},
                                         directory_rva=0x5000)
        # two descriptors plus the null terminator, 20 bytes each
        assert blob[40:60] == bytes(20)

    def test_name_rvas_are_reported_for_every_import(self, imports):
        imports.declare('kernel32.dll', 'GetProcAddress')
        imports.declare('msvcrt.dll', 'setlocale')
        _, names = build_import_directory(imports.refs, iat_rva={},
                                          directory_rva=0x5000)
        assert set(names) == {r.symbol for r in imports.refs}

    def test_dll_names_appear_in_the_blob(self, imports):
        imports.declare('kernel32.dll', 'GetProcAddress')
        blob, _ = build_import_directory(imports.refs, iat_rva={},
                                         directory_rva=0x5000)
        assert b'kernel32.dll\x00' in blob
        assert b'GetProcAddress\x00' in blob

    def test_empty_import_set_yields_only_the_terminator(self):
        blob, names = build_import_directory((), iat_rva={}, directory_rva=0x5000)
        assert blob == bytes(20) and names == {}
