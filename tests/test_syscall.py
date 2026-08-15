"""Syscall table lookups, target selection, and stub decode/emit."""

import struct

import pytest

from x86x64.errors import SyscallError
from x86x64.syscall import (
    STUB_SIZE,
    StubInfo,
    StubMechanism,
    SyscallEntry,
    SyscallTable,
    SyscallTarget,
    decode_stub,
    emit_unmapped_stub,
    emit_x64_stub,
    translate_stub,
)


@pytest.fixture
def table():
    return SyscallTable()


class TestSyscallTarget:
    @pytest.mark.parametrize('value', ['win2000', 'WIN2000', 'Win2000'])
    def test_parse_is_case_insensitive(self, value):
        assert SyscallTarget.parse(value) is SyscallTarget.WIN2000

    def test_parse_passes_through_enum(self):
        assert SyscallTarget.parse(SyscallTarget.WIN10) is SyscallTarget.WIN10

    def test_bad_target_raises(self):
        with pytest.raises(SyscallError, match="must be 'win2000' or 'win10'"):
            SyscallTarget.parse('winxp')


class TestSyscallEntry:
    def test_zw_names_are_aliases(self):
        assert SyscallEntry(1, 2, 3, 'ZwCreateFile').is_alias
        assert not SyscallEntry(1, 2, 3, 'NtCreateFile').is_alias

    def test_alias_maps_to_nt_name(self):
        assert SyscallEntry(1, 2, 3, 'ZwCreateFile').nt_name == 'NtCreateFile'

    def test_stack_bytes_follow_arg_count(self):
        assert SyscallEntry(0, 0, 11, 'NtCreateFile').stack_bytes == 44

    def test_number_depends_on_target(self):
        e = SyscallEntry(0x10, 0x18, 6, 'NtAllocateVirtualMemory')
        assert e.number_for(SyscallTarget.WIN2000) == 0x10
        assert e.number_for(SyscallTarget.WIN10) == 0x18


class TestSyscallTable:
    def test_loads_the_full_ssdt(self, table):
        assert len(table.services()) > 200

    def test_known_service_lookup(self, table):
        entry = table.require('NtAllocateVirtualMemory')
        assert entry.win2000_nr == 0x10
        assert entry.n_args == 6

    def test_lookup_by_number(self, table):
        assert table.by_number(0x10).name == 'NtAllocateVirtualMemory'

    def test_unknown_service_raises(self, table):
        with pytest.raises(SyscallError, match='unknown system service'):
            table.require('NtNotARealService')

    def test_membership(self, table):
        assert 'NtAllocateVirtualMemory' in table
        assert 'NtDefinitelyFake' not in table

    def test_services_excludes_aliases_by_default(self, table):
        assert all(not e.is_alias for e in table.services())


class TestResolution:
    def test_win2000_target_keeps_the_original_index(self, table):
        assert table.resolve('NtAllocateVirtualMemory', 0x10) == 0x10

    def test_win10_target_uses_the_mapped_index(self, table):
        table.target = SyscallTarget.WIN10
        assert table.resolve('NtAllocateVirtualMemory', 0x10) == 0x18

    def test_win10_target_returns_zero_when_unmapped(self, table):
        table.target = SyscallTarget.WIN10
        table.replace(SyscallEntry(0x99, 0, 2, 'NtGoneInWin10'))
        assert table.resolve('NtGoneInWin10', 0x99) == 0

    def test_win2000_target_falls_back_to_the_supplied_number(self, table):
        assert table.resolve('NtUnknownToUs', 0x1234) == 0x1234

    def test_is_mappable_is_always_true_for_win2000(self, table):
        table.replace(SyscallEntry(0x99, 0, 2, 'NtGoneInWin10'))
        assert table.is_mappable('NtGoneInWin10')

    def test_is_mappable_is_false_for_unmapped_win10(self, table):
        table.target = SyscallTarget.WIN10
        table.replace(SyscallEntry(0x99, 0, 2, 'NtGoneInWin10'))
        assert not table.is_mappable('NtGoneInWin10')

    def test_two_tables_can_hold_different_targets(self):
        """The globals in the legacy module made this impossible."""
        a = SyscallTable(target='win2000')
        b = SyscallTable(target='win10')
        assert a.resolve('NtAllocateVirtualMemory', 0x10) == 0x10
        assert b.resolve('NtAllocateVirtualMemory', 0x10) == 0x18


class TestWin10Map:
    def test_apply_updates_numbers(self, table):
        changed = table.apply_win10_map({'NtAllocateVirtualMemory': 0x99})
        assert changed == 1
        assert table.require('NtAllocateVirtualMemory').win10_nr == 0x99

    def test_zw_alias_follows_its_nt_sibling(self, table):
        table.add(SyscallEntry(0x10, 0x18, 6, 'ZwAllocateVirtualMemory'))
        table.apply_win10_map({'NtAllocateVirtualMemory': 0x99})
        assert table.require('ZwAllocateVirtualMemory').win10_nr == 0x99

    def test_reapplying_the_same_map_changes_nothing(self, table):
        table.apply_win10_map({'NtAllocateVirtualMemory': 0x99})
        assert table.apply_win10_map({'NtAllocateVirtualMemory': 0x99}) == 0

    def test_unknown_names_are_ignored(self, table):
        assert table.apply_win10_map({'NtWhatever': 0x1}) == 0


class TestCoverage:
    def test_win2000_target_is_fully_covered(self, table):
        mapped, total, unmapped = table.coverage()
        assert mapped == total and unmapped == []

    def test_win10_target_reports_gaps(self, table):
        table.target = SyscallTarget.WIN10
        mapped, total, unmapped = table.coverage()
        assert mapped < total
        assert len(unmapped) == total - mapped

    def test_rows_carry_the_active_target(self, table):
        rows = table.to_rows()
        assert rows[0]['target'] == 'win2000'
        assert rows[0]['x64_nr'] == rows[0]['win2000_nr']


class TestStubDecode:
    def _stub(self, nr=0x10, ret_pop=0x18, mech=b'\xcd\x2e', lea=True):
        body = bytes([0xB8]) + struct.pack('<I', nr)
        body += b'\x8d\x54\x24\x04' if lea else b'\x8b\xd4'
        body += mech
        body += b'\xc2' + struct.pack('<H', ret_pop)
        return body.ljust(STUB_SIZE, b'\x90')

    def test_decodes_int2e_stub(self):
        info = decode_stub(self._stub(), name='NtAllocateVirtualMemory')
        assert info.win2000_nr == 0x10
        assert info.n_args == 6
        assert info.mechanism == StubMechanism.INT2E

    def test_decodes_sysenter_stub(self):
        info = decode_stub(self._stub(mech=b'\x0f\x34'), name='NtClose')
        assert info.mechanism == StubMechanism.SYSENTER

    def test_decodes_mov_edx_esp_variant(self):
        assert decode_stub(self._stub(lea=False), name='NtClose') is not None

    def test_ret_near_means_zero_args(self):
        body = (bytes([0xB8]) + struct.pack('<I', 5) + b'\x8d\x54\x24\x04'
                + b'\xcd\x2e' + b'\xc3')
        info = decode_stub(body.ljust(STUB_SIZE, b'\x90'), name='NtX')
        assert info.n_args == 0 and info.ret_pop == 0

    def test_non_stub_export_is_rejected(self):
        # NtCurrentTeb is a real export but an ordinary function.
        assert decode_stub(b'\x64\xa1\x18\x00\x00\x00\xc3'.ljust(16, b'\x90')) is None

    def test_truncated_input_is_rejected(self):
        assert decode_stub(b'\xb8\x10') is None

    def test_wrong_middle_instruction_is_rejected(self):
        body = bytes([0xB8]) + struct.pack('<I', 5) + b'\x90\x90\x90\x90\xcd\x2e\xc3'
        assert decode_stub(body) is None


class TestStubEmit:
    def test_emits_the_canonical_four_instruction_form(self):
        assert emit_x64_stub(0x18) == (
            b'\x4c\x8b\xd1'                    # mov r10, rcx
            b'\xb8\x18\x00\x00\x00'            # mov eax, 0x18
            b'\x0f\x05'                        # syscall
            b'\xc3')                           # ret

    def test_moves_rcx_to_r10_first(self):
        """syscall clobbers RCX, so argument one must be parked in R10."""
        assert emit_x64_stub(1).startswith(b'\x4c\x8b\xd1')

    def test_number_lands_in_eax(self):
        blob = emit_x64_stub(0x1234)
        assert struct.unpack_from('<I', blob, 4)[0] == 0x1234

    def test_tail_ret_can_be_suppressed(self):
        assert not emit_x64_stub(1, tail_ret=False).endswith(b'\xc3')

    def test_oversized_number_is_rejected(self):
        with pytest.raises(SyscallError, match='does not fit in eax'):
            emit_x64_stub(0x1_0000_0000)

    def test_unmapped_stub_traps_then_returns(self):
        assert emit_unmapped_stub() == b'\xcc\xc3'


class TestStubTranslation:
    def _info(self, name='NtAllocateVirtualMemory', nr=0x10):
        return StubInfo(rva=0x1000, name=name, win2000_nr=nr, n_args=6,
                        ret_pop=0x18)

    def test_win2000_target_keeps_the_index(self, table):
        result = translate_stub(self._info(), table=table)
        assert result.mapped and result.number == 0x10

    def test_win10_target_substitutes_the_index(self, table):
        table.target = SyscallTarget.WIN10
        result = translate_stub(self._info(), table=table)
        assert result.number == 0x18
        assert struct.unpack_from('<I', result.code, 4)[0] == 0x18

    def test_unmapped_win10_service_becomes_a_trap(self, table):
        table.target = SyscallTarget.WIN10
        table.replace(SyscallEntry(0x99, 0, 2, 'NtGoneInWin10'))
        result = translate_stub(self._info('NtGoneInWin10', 0x99), table=table)
        assert not result.mapped
        assert result.code == b'\xcc\xc3'
        assert 'no Win10 x64 equivalent' in result.note

    def test_unmapped_service_still_maps_under_win2000(self, table):
        table.replace(SyscallEntry(0x99, 0, 2, 'NtGoneInWin10'))
        result = translate_stub(self._info('NtGoneInWin10', 0x99), table=table)
        assert result.mapped and result.number == 0x99
