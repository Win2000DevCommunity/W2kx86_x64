"""TEB remapping and stdcall/cdecl to Microsoft x64 argument placement."""

import pytest

from x86x64.abi import callconv, teb


class TestTebTable:
    def test_peb_moves_from_0x30_to_0x60(self):
        assert teb.fs_to_gs(0x30) == 0x60

    @pytest.mark.parametrize('fs,gs', [
        (0x00, 0x00),   # ExceptionList
        (0x04, 0x08),   # StackBase
        (0x08, 0x10),   # StackLimit
        (0x18, 0x30),   # Self
        (0x30, 0x60),   # PEB
        (0x34, 0x68),   # LastErrorValue
    ])
    def test_known_offsets(self, fs, gs):
        assert teb.fs_to_gs(fs) == gs

    def test_unknown_offsets_pass_through(self):
        assert teb.fs_to_gs(0xE10) == 0xE10

    def test_mapping_is_injective(self):
        gs = [f.gs_offset for f in teb.TEB_FIELDS]
        assert len(gs) == len(set(gs))

    def test_offsets_increase_monotonically(self):
        fields = list(teb.TEB_FIELDS)
        assert all(a.fs_offset < b.fs_offset for a, b in zip(fields, fields[1:]))
        assert all(a.gs_offset < b.gs_offset for a, b in zip(fields, fields[1:]))

    def test_lookup_by_name(self):
        assert teb.field_by_name('ProcessEnvironmentBlock').gs_offset == 0x60

    def test_reverse_lookup(self):
        assert teb.field_at_gs(0x60).name == 'ProcessEnvironmentBlock'

    def test_known_offset_predicate(self):
        assert teb.is_known_fs_offset(0x30)
        assert not teb.is_known_fs_offset(0x1234)


class TestTebWidths:
    def test_pointer_fields_are_qwords(self):
        assert teb.access_width(0x60) == 8
        assert teb.operand_size(0x60) == 'qword'

    def test_last_error_stays_a_dword(self):
        """LastErrorValue does not widen, unlike the pointers before it."""
        assert teb.access_width(0x68) == 4
        assert teb.operand_size(0x68) == 'dword'

    def test_unknown_offsets_default_to_qword(self):
        assert teb.access_width(0x999) == 8

    def test_pointer_set_excludes_the_dword_fields(self):
        assert 0x60 in teb.POINTER_GS_OFFSETS
        assert 0x68 not in teb.POINTER_GS_OFFSETS


class TestCallConv:
    def test_stdcall_callee_cleans_up(self):
        assert callconv.CallConv.STDCALL.callee_cleans_stack

    def test_cdecl_caller_cleans_up(self):
        assert not callconv.CallConv.CDECL.callee_cleans_stack

    def test_fastcall_passes_two_in_registers(self):
        assert callconv.CallConv.FASTCALL.register_args == ('ecx', 'edx')

    def test_thiscall_passes_one_in_ecx(self):
        assert callconv.CallConv.THISCALL.register_args == ('ecx',)

    def test_stdcall_passes_nothing_in_registers(self):
        assert callconv.CallConv.STDCALL.register_args == ()


class TestArgLocation:
    @pytest.mark.parametrize('index,reg', [
        (0, 'rcx'), (1, 'rdx'), (2, 'r8'), (3, 'r9'),
    ])
    def test_first_four_go_in_registers(self, index, reg):
        loc = callconv.arg_location(index)
        assert loc.in_register and loc.register == reg

    def test_fifth_argument_goes_on_the_stack(self):
        loc = callconv.arg_location(4)
        assert not loc.in_register
        assert loc.stack_offset == 0x20

    def test_callee_sees_stack_args_eight_bytes_higher(self):
        """The return address the call pushed sits between the two views."""
        caller = callconv.arg_location(4, caller_side=True)
        callee = callconv.arg_location(4, caller_side=False)
        assert callee.stack_offset - caller.stack_offset == 8

    def test_stack_args_are_eight_bytes_apart(self):
        a = callconv.arg_location(4).stack_offset
        b = callconv.arg_location(5).stack_offset
        assert b - a == 8

    def test_32bit_width_uses_the_dword_views(self):
        assert callconv.arg_location(0, width=32).register == 'ecx'

    def test_negative_index_is_rejected(self):
        with pytest.raises(ValueError, match='negative'):
            callconv.arg_location(-1)

    def test_bulk_locations(self):
        locs = callconv.arg_locations(6)
        assert [l.register for l in locs[:4]] == ['rcx', 'rdx', 'r8', 'r9']
        assert all(l.stack_offset is not None for l in locs[4:])


class TestStackReservation:
    @pytest.mark.parametrize('count,expected', [
        (0, 32), (1, 32), (4, 32), (5, 48), (6, 48), (7, 64), (8, 64),
    ])
    def test_reservation_size(self, count, expected):
        assert callconv.stack_bytes_for_args(count) == expected

    def test_shadow_space_is_always_reserved(self):
        assert callconv.stack_bytes_for_args(0) == callconv.SHADOW_SPACE

    @pytest.mark.parametrize('count', range(0, 12))
    def test_reservation_keeps_the_stack_aligned(self, count):
        assert callconv.stack_bytes_for_args(count) % 16 == 0


class TestX86FrameMapping:
    def test_first_argument_is_at_ebp_plus_8(self):
        assert callconv.x86_arg_index(8) == 0

    @pytest.mark.parametrize('disp,index', [
        (8, 0), (0xC, 1), (0x10, 2), (0x14, 3), (0x18, 4),
    ])
    def test_argument_indices(self, disp, index):
        assert callconv.x86_arg_index(disp) == index

    def test_saved_ebp_and_locals_are_not_arguments(self):
        assert callconv.x86_arg_index(4) is None
        assert callconv.x86_arg_index(0) is None
        assert callconv.x86_arg_index(-4) is None

    def test_unaligned_displacement_is_not_an_argument(self):
        assert callconv.x86_arg_index(9) is None

    @pytest.mark.parametrize('disp,home', [
        (8, 0x10), (0xC, 0x18), (0x10, 0x20), (0x14, 0x28), (0x18, 0x30),
    ])
    def test_home_slot_mapping(self, disp, home):
        assert callconv.x86_disp_to_rbp_home(disp) == home

    def test_register_homes_are_contiguous(self):
        homes = [callconv.x86_disp_to_rbp_home(8 + i * 4) for i in range(4)]
        assert homes == [0x10, 0x18, 0x20, 0x28]

    def test_stack_args_continue_past_the_homes(self):
        assert callconv.x86_disp_to_rbp_home(0x18) == 0x30

    def test_slot_helper_matches_disp_helper(self):
        for slot in range(6):
            assert callconv.arg_slot_to_rbp_home(slot) == \
                callconv.x86_disp_to_rbp_home(8 + slot * 4)

    def test_out_of_range_displacement_is_rejected(self):
        assert callconv.x86_disp_to_rbp_home(0x400) is None

    def test_local_byte_mapping_handles_non_slot_offsets(self):
        assert callconv.x86_disp_to_rbp_local(9) == 0x11


class TestMisc:
    def test_ret_pop_implies_arg_count(self):
        assert callconv.ret_pop_to_arg_count(0x18) == 6
        assert callconv.ret_pop_to_arg_count(0) == 0

    def test_alignment_predicate(self):
        assert callconv.is_aligned(0x1000)
        assert not callconv.is_aligned(0x1008)
