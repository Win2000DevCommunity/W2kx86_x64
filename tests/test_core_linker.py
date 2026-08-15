"""
Linker behaviour, with emphasis on the property the old shift pass lacked.

The translator used to bake absolute addresses into the blob and then, when a
growing ``.text`` pushed ``.data`` further out, re-scan for ``movabs`` byte
patterns and add the delta.  ``TestSectionShift`` below encodes what should
happen instead: growth is absorbed by re-layout, references follow their
symbols, and bytes that merely look like addresses are never touched.
"""

import struct

import pytest

from x86x64.core import (
    IMAGE_REL_BASED_DIR64,
    Linker,
    ObjectFile,
    RelocKind,
    SectionFlags,
    align_up,
    build_base_reloc_blocks,
)
from x86x64.errors import LayoutError, UndefinedSymbolError

BASE = 0x8000_0000
MOVABS_RDX = b'\x48\xba'      # movabs rdx, imm64
MOVABS_RAX = b'\x48\xb8'
RET = b'\xc3'


def make_obj(name='t.obj'):
    return ObjectFile(name)


class TestAlignUp:
    @pytest.mark.parametrize('value,boundary,expected', [
        (0, 0x1000, 0), (1, 0x1000, 0x1000), (0x1000, 0x1000, 0x1000),
        (0x1001, 0x1000, 0x2000), (0x123, 0x200, 0x200),
    ])
    def test_rounds_up(self, value, boundary, expected):
        assert align_up(value, boundary) == expected


class TestBasicLinking:
    def test_symbol_gets_section_address(self):
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        text.emit(RET)
        obj.define('entry', '.text', 0)

        result = Linker(image_base=BASE).add_object(obj).link()
        assert result.address_of('entry') == BASE + result.layout.rva_of('.text')

    def test_abs64_reloc_resolves_to_target(self):
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        data = obj.section('.data', SectionFlags.data())
        data.emit(b'hello\x00')
        obj.define('msg', '.data', 0)

        text.emit(MOVABS_RDX)
        text.emit_reloc(RelocKind.ABS64, 'msg')
        text.emit(RET)

        result = Linker(image_base=BASE).add_object(obj).link()
        blob = result.section_bytes('.text')
        assert struct.unpack_from('<Q', blob, 2)[0] == result.address_of('msg')

    def test_rel32_call_resolves_between_sections(self):
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        text.emit(b'\xe8')
        text.emit_reloc(RelocKind.REL32, 'callee')
        text.emit(RET)
        callee_off = text.tell()
        text.emit(RET)
        obj.define('callee', '.text', callee_off)

        result = Linker(image_base=BASE).add_object(obj).link()
        blob = result.section_bytes('.text')
        disp = struct.unpack_from('<i', blob, 1)[0]
        # site 1..5, so the next instruction starts at 5
        assert 5 + disp == callee_off

    def test_undefined_symbol_is_reported_with_site(self):
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        text.emit(MOVABS_RAX)
        text.emit_reloc(RelocKind.ABS64, 'nowhere')

        with pytest.raises(UndefinedSymbolError, match='nowhere'):
            Linker(image_base=BASE).add_object(obj).link()

    def test_absolute_symbols_are_usable_as_targets(self):
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        text.emit(MOVABS_RAX)
        text.emit_reloc(RelocKind.ABS64, 'KUSER_SHARED_DATA')

        lk = Linker(image_base=BASE).add_object(obj)
        lk.define_absolute('KUSER_SHARED_DATA', 0x7FFE_0000)
        blob = lk.link().section_bytes('.text')
        assert struct.unpack_from('<Q', blob, 2)[0] == 0x7FFE_0000


class TestLayout:
    def test_sections_do_not_overlap(self):
        obj = make_obj()
        obj.section('.text', SectionFlags.text()).emit(b'\x90' * 0x1800)
        obj.section('.data', SectionFlags.data()).emit(b'\x01' * 0x900)
        obj.section('.rdata', SectionFlags.rdata()).emit(b'\x02' * 0x40)

        layout = Linker(image_base=BASE).add_object(obj).link().layout
        placed = sorted(layout.sections, key=lambda p: p.rva)
        for a, b in zip(placed, placed[1:]):
            assert a.end_rva <= b.rva, f'{a} overlaps {b}'

    def test_canonical_section_order(self):
        obj = make_obj()
        for name in ('.reloc', '.data', '.text', '.rdata'):
            obj.section(name).emit(b'\x00' * 16)
        layout = Linker(image_base=BASE).add_object(obj).link().layout
        order = [p.name for p in layout.sections]
        assert order.index('.text') < order.index('.rdata') < order.index('.data')
        assert order[-1] == '.reloc'

    def test_sections_are_page_aligned(self):
        obj = make_obj()
        obj.section('.text', SectionFlags.text()).emit(b'\x90' * 0x123)
        obj.section('.data').emit(b'\x00' * 0x17)
        layout = Linker(image_base=BASE).add_object(obj).link().layout
        for p in layout.sections:
            assert p.rva % 0x1000 == 0

    def test_image_size_covers_every_section(self):
        obj = make_obj()
        obj.section('.text', SectionFlags.text()).emit(b'\x90' * 0x2345)
        obj.section('.data').emit(b'\x00' * 0x1234)
        layout = Linker(image_base=BASE).add_object(obj).link().layout
        assert layout.image_size >= max(p.end_rva for p in layout.sections)


class TestSectionShift:
    """The regression the whole object model exists to prevent."""

    def _build(self, code_padding: int) -> ObjectFile:
        """
        A miniature of the failing cmd.exe path.

        ``.text`` holds ``movabs rdx, locale_str`` (the setlocale argument) and
        a 64-bit constant that merely *looks* like an image pointer.  Growing
        ``code_padding`` stands in for the post-processing passes that expand
        translated code and push ``.data`` outward.
        """
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        data = obj.section('.data', SectionFlags.data())

        data.emit(b'\x00' * 0x4538)
        locale_off = data.tell()
        data.emit('French_France.1252\x00'.encode('utf-16-le'))
        obj.define('locale_str', '.data', locale_off)

        text.emit(b'\x90' * code_padding)
        obj.define('call_site', '.text', text.tell())
        text.emit(MOVABS_RDX)
        text.emit_reloc(RelocKind.ABS64, 'locale_str')
        # A genuine constant in the same shape as an address. The old scanner
        # matched on bytes and would have corrupted exactly this.
        obj.define('magic', '.text', text.tell())
        text.emit(MOVABS_RAX + struct.pack('<Q', 0x8004_4538))
        text.emit(RET)
        return obj

    def _locale_pointer(self, result):
        off = result.rva_of('call_site') - result.layout.rva_of('.text') + 2
        return struct.unpack_from('<Q', result.section_bytes('.text'), off)[0]

    def _magic_constant(self, result):
        off = result.rva_of('magic') - result.layout.rva_of('.text') + 2
        return struct.unpack_from('<Q', result.section_bytes('.text'), off)[0]

    def test_pointer_is_correct_before_growth(self):
        result = Linker(image_base=BASE).add_object(self._build(0x100)).link()
        assert self._locale_pointer(result) == result.address_of('locale_str')

    def test_pointer_follows_data_when_code_grows(self):
        small = Linker(image_base=BASE).add_object(self._build(0x100)).link()
        large = Linker(image_base=BASE).add_object(self._build(0x3000)).link()

        # .data really did move -- this is the "shift" the old pass chased.
        assert large.layout.rva_of('.data') > small.layout.rva_of('.data')
        # ...and the reference tracked it with no fixup pass in sight.
        assert self._locale_pointer(large) == large.address_of('locale_str')

    def test_lookalike_constant_is_never_rewritten(self):
        """The false-positive that corrupted real data in the byte scanner."""
        for padding in (0x100, 0x3000, 0x9000):
            result = Linker(image_base=BASE).add_object(self._build(padding)).link()
            assert self._magic_constant(result) == 0x8004_4538

    def test_pointed_to_string_survives_intact(self):
        result = Linker(image_base=BASE).add_object(self._build(0x3000)).link()
        off = result.rva_of('locale_str') - result.layout.rva_of('.data')
        raw = result.section_bytes('.data')[off:off + 36]
        assert raw.decode('utf-16-le').rstrip('\x00') == 'French_France.1252'

    def test_relink_at_new_base_moves_every_reference(self):
        lk = Linker(image_base=BASE).add_object(self._build(0x100))
        first = lk.link()
        second = lk.relink(image_base=0x1_4000_0000)

        assert self._locale_pointer(first) == first.address_of('locale_str')
        assert self._locale_pointer(second) == second.address_of('locale_str')
        assert self._locale_pointer(second) != self._locale_pointer(first)

    def test_relinking_repeatedly_is_stable(self):
        """No accumulated drift -- the old pass double-added its delta."""
        lk = Linker(image_base=BASE).add_object(self._build(0x100))
        results = [lk.link() for _ in range(4)]
        pointers = {self._locale_pointer(r) for r in results}
        assert len(pointers) == 1


class TestMultipleObjects:
    def test_cross_object_reference_resolves(self):
        a, b = make_obj('a.obj'), make_obj('b.obj')
        a.section('.text', SectionFlags.text()).emit(b'\xe8')
        a.section('.text').emit_reloc(RelocKind.REL32, 'helper')
        a.section('.text').emit(RET)

        btext = b.section('.text', SectionFlags.text())
        btext.emit(b'\x90')
        b.define('helper', '.text', 0)

        result = Linker(image_base=BASE).add_objects([a, b]).link()
        assert 'helper' in result.addresses

    def test_contributions_are_concatenated(self):
        a, b = make_obj('a.obj'), make_obj('b.obj')
        a.section('.data').emit(b'AAAA')
        b.section('.data').emit(b'BBBB')
        result = Linker(image_base=BASE).add_objects([a, b]).link()
        blob = result.section_bytes('.data')
        assert b'AAAA' in blob and b'BBBB' in blob

    def test_second_object_symbols_are_rebased(self):
        a, b = make_obj('a.obj'), make_obj('b.obj')
        a.section('.data').emit(b'\x11' * 0x40)
        b.section('.data').emit(b'\x22' * 0x10)
        b.define('bsym', '.data', 0)
        result = Linker(image_base=BASE).add_objects([a, b]).link()
        # b's contribution starts after a's, so its symbol cannot be at +0.
        assert result.rva_of('bsym') > result.layout.rva_of('.data')


class TestImports:
    def test_import_gets_an_iat_slot(self):
        obj = make_obj()
        sym = obj.declare_import('msvcrt.dll', 'setlocale')
        text = obj.section('.text', SectionFlags.text())
        text.emit(MOVABS_RAX)
        text.emit_reloc(RelocKind.ABS64, sym.name)

        result = Linker(image_base=BASE).add_object(obj).link()
        assert sym.name in result.iat_slots
        slot = result.iat_slots[sym.name]
        assert struct.unpack_from('<Q', result.section_bytes('.text'), 2)[0] == slot

    def test_distinct_imports_get_distinct_slots(self):
        obj = make_obj()
        a = obj.declare_import('kernel32.dll', 'GetProcAddress')
        b = obj.declare_import('kernel32.dll', 'GetModuleHandleW')
        obj.section('.text', SectionFlags.text()).emit(RET)
        result = Linker(image_base=BASE).add_object(obj).link()
        assert result.iat_slots[a.name] != result.iat_slots[b.name]

    def test_repeated_declaration_reuses_one_slot(self):
        obj = make_obj()
        first = obj.declare_import('msvcrt.dll', 'setlocale')
        second = obj.declare_import('msvcrt.dll', 'setlocale')
        assert first is second or first.name == second.name
        obj.section('.text', SectionFlags.text()).emit(RET)
        result = Linker(image_base=BASE).add_object(obj).link()
        assert len(result.iat_slots) == 1


class TestBaseRelocations:
    def test_abs64_produces_a_base_reloc(self):
        obj = make_obj()
        obj.section('.data').emit(b'\x00' * 8)
        obj.define('t', '.data', 0)
        text = obj.section('.text', SectionFlags.text())
        text.emit(MOVABS_RAX)
        text.emit_reloc(RelocKind.ABS64, 't')

        result = Linker(image_base=BASE).add_object(obj).link()
        assert (result.layout.rva_of('.text') + 2, IMAGE_REL_BASED_DIR64) \
            in result.base_relocs

    def test_rel32_produces_no_base_reloc(self):
        obj = make_obj()
        text = obj.section('.text', SectionFlags.text())
        text.emit(b'\xe8')
        text.emit_reloc(RelocKind.REL32, 'here')
        obj.define('here', '.text', text.tell())
        text.emit(RET)
        assert Linker(image_base=BASE).add_object(obj).link().base_relocs == []

    def test_blocks_are_page_grouped_and_padded(self):
        relocs = [(0x1000, 10), (0x1008, 10), (0x2000, 10)]
        blob = build_base_reloc_blocks(relocs)
        page, size = struct.unpack_from('<II', blob, 0)
        assert page == 0x1000
        assert size % 4 == 0
        page2, _ = struct.unpack_from('<II', blob, size)
        assert page2 == 0x2000

    def test_entry_encodes_type_and_page_offset(self):
        blob = build_base_reloc_blocks([(0x1008, 10)])
        entry = struct.unpack_from('<H', blob, 8)[0]
        assert entry >> 12 == 10
        assert entry & 0xFFF == 8

    def test_empty_input_yields_empty_directory(self):
        assert build_base_reloc_blocks([]) == b''


class TestSectionGuards:
    def test_reloc_outside_section_is_rejected(self):
        obj = make_obj()
        sec = obj.section('.text', SectionFlags.text())
        sec.emit(b'\x90\x90')
        with pytest.raises(LayoutError, match='outside section'):
            sec.reloc(0, RelocKind.ABS64, 'x')

    def test_patch_past_end_is_rejected(self):
        sec = make_obj().section('.text', SectionFlags.text())
        sec.emit(b'\x90' * 4)
        with pytest.raises(LayoutError, match='exceeds section'):
            sec.patch(2, b'\x00' * 8)

    def test_pristine_data_keeps_relocation_fields_zero(self):
        obj = make_obj()
        obj.section('.data').emit(b'\x00' * 8)
        obj.define('t', '.data', 0)
        text = obj.section('.text', SectionFlags.text())
        text.emit(MOVABS_RAX)
        text.emit_reloc(RelocKind.ABS64, 't')
        assert text.data[2:10] == bytes(8)

    def test_linking_does_not_mutate_pristine_bytes(self):
        obj = make_obj()
        obj.section('.data').emit(b'\x00' * 8)
        obj.define('t', '.data', 0)
        text = obj.section('.text', SectionFlags.text())
        text.emit(MOVABS_RAX)
        text.emit_reloc(RelocKind.ABS64, 't')

        before = text.data
        Linker(image_base=BASE).add_object(obj).link()
        assert text.data == before

    def test_non_power_of_two_alignment_is_rejected(self):
        from x86x64.core import Section
        with pytest.raises(LayoutError, match='power of two'):
            Section('.text', alignment=24)
