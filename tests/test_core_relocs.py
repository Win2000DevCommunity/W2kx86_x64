"""Relocation arithmetic and field encoding."""

import struct

import pytest

from x86x64.core import (
    IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGHLOW,
    RelocKind,
    Relocation,
    apply_relocation,
    base_reloc_type,
    compute_value,
    encode_value,
)
from x86x64.errors import RelocationRangeError


class TestRelocKind:
    @pytest.mark.parametrize('kind,width', [
        (RelocKind.ABS64, 8), (RelocKind.ABS32, 4), (RelocKind.RVA32, 4),
        (RelocKind.REL32, 4), (RelocKind.REL8, 1), (RelocKind.SECREL32, 4),
        (RelocKind.SECTION16, 2),
    ])
    def test_widths(self, kind, width):
        assert kind.width == width

    def test_only_rel_kinds_are_pc_relative(self):
        pc = {k for k in RelocKind if k.pc_relative}
        assert pc == {RelocKind.REL32, RelocKind.REL8}

    def test_only_absolute_kinds_need_base_relocs(self):
        need = {k for k in RelocKind if k.needs_base_reloc}
        assert need == {RelocKind.ABS64, RelocKind.ABS32}

    def test_base_reloc_type_codes(self):
        assert base_reloc_type(RelocKind.ABS64) == IMAGE_REL_BASED_DIR64
        assert base_reloc_type(RelocKind.ABS32) == IMAGE_REL_BASED_HIGHLOW
        assert base_reloc_type(RelocKind.REL32) is None


class TestComputeValue:
    BASE = 0x8000_0000

    def _reloc(self, kind, addend=0, **kw):
        return Relocation(0, kind, 'target', addend, **kw)

    def test_abs64_is_the_target_itself(self):
        v = compute_value(self._reloc(RelocKind.ABS64), 0x8004_4538,
                          site_va=0x8001_0000, image_base=self.BASE)
        assert v == 0x8004_4538

    def test_addend_is_added(self):
        v = compute_value(self._reloc(RelocKind.ABS64, addend=0x10), 0x8004_4538,
                          site_va=0x8001_0000, image_base=self.BASE)
        assert v == 0x8004_4548

    def test_rva32_subtracts_image_base(self):
        v = compute_value(self._reloc(RelocKind.RVA32), 0x8004_4538,
                          site_va=0x8001_0000, image_base=self.BASE)
        assert v == 0x4_4538

    def test_secrel32_subtracts_section_base(self):
        v = compute_value(self._reloc(RelocKind.SECREL32), 0x8004_4538,
                          site_va=0x8001_0000, image_base=self.BASE,
                          section_base=0x8004_0000)
        assert v == 0x4538

    def test_rel32_measures_from_end_of_field(self):
        # call at 0x1000, field at 0x1001..0x1005, target 0x1100 -> 0xFB
        v = compute_value(self._reloc(RelocKind.REL32), 0x8000_1100,
                          site_va=0x8000_1001, image_base=self.BASE)
        assert v == 0x1100 - (0x1001 + 4)

    def test_rel32_backward_branch_is_negative(self):
        v = compute_value(self._reloc(RelocKind.REL32), 0x8000_1000,
                          site_va=0x8000_2001, image_base=self.BASE)
        assert v < 0

    def test_pcrel_adjust_accounts_for_trailing_bytes(self):
        # mov dword [rip+disp32], imm32: 4 bytes follow the displacement.
        plain = compute_value(self._reloc(RelocKind.REL32), 0x8000_1100,
                              site_va=0x8000_1001, image_base=self.BASE)
        adjusted = compute_value(self._reloc(RelocKind.REL32, pcrel_adjust=4),
                                 0x8000_1100, site_va=0x8000_1001,
                                 image_base=self.BASE)
        assert adjusted == plain - 4

    def test_section16_yields_the_index(self):
        v = compute_value(self._reloc(RelocKind.SECTION16), 0x8004_0000,
                          site_va=0x8000_1000, image_base=self.BASE,
                          section_index=3)
        assert v == 3


class TestEncodeValue:
    def test_abs64_round_trips(self):
        blob = encode_value(RelocKind.ABS64, 0x8004_4538)
        assert struct.unpack('<Q', blob)[0] == 0x8004_4538

    def test_rel32_encodes_negative_two_complement(self):
        assert encode_value(RelocKind.REL32, -5) == struct.pack('<i', -5)

    def test_rel8_boundaries(self):
        assert encode_value(RelocKind.REL8, 127) == b'\x7f'
        assert encode_value(RelocKind.REL8, -128) == b'\x80'

    @pytest.mark.parametrize('kind,value', [
        (RelocKind.REL8, 128),
        (RelocKind.REL8, -129),
        (RelocKind.REL32, 0x8000_0000),
        (RelocKind.ABS32, 0x1_0000_0000),
        (RelocKind.SECTION16, 0x1_0000),
    ])
    def test_out_of_range_rejected(self, kind, value):
        with pytest.raises(RelocationRangeError):
            encode_value(kind, value)

    def test_range_error_reports_kind_and_site(self):
        with pytest.raises(RelocationRangeError, match='rel8.*out of range.*mysite'):
            encode_value(RelocKind.REL8, 500, site='mysite')


class TestApplyRelocation:
    def test_writes_into_buffer(self):
        buf = bytearray(b'\x48\xb8' + bytes(8))
        r = Relocation(2, RelocKind.ABS64, 'locale_str')
        apply_relocation(buf, r, 0x8004_4538, site_va=0x8001_0000,
                         image_base=0x8000_0000)
        assert struct.unpack_from('<Q', buf, 2)[0] == 0x8004_4538
        assert buf[:2] == b'\x48\xb8'   # opcode untouched

    def test_offset_past_end_is_rejected(self):
        buf = bytearray(4)
        r = Relocation(2, RelocKind.ABS64, 'x')
        with pytest.raises(RelocationRangeError):
            apply_relocation(buf, r, 0, site_va=0, image_base=0)

    def test_applying_twice_is_idempotent(self):
        # The property the old byte-scanning shift pass could not offer.
        buf = bytearray(10)
        r = Relocation(2, RelocKind.ABS64, 'x')
        for _ in range(3):
            apply_relocation(buf, r, 0x8004_4538, site_va=0x8001_0000,
                             image_base=0x8000_0000)
        assert struct.unpack_from('<Q', buf, 2)[0] == 0x8004_4538
